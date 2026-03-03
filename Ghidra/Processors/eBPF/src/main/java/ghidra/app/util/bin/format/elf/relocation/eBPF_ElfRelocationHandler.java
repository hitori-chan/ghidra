/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.elf.relocation;

import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.util.Msg;

/**
 * eBPF ELF relocation handler with Solana SBF support.
 *
 * Handles standard Linux eBPF relocations plus Solana-specific external symbol
 * relocations. Solana eBPF programs use R_BPF_64_32 for both internal function
 * calls and external syscall calls:
 *
 * - Internal functions: symbol.isFunction(), st_value != 0 → PC-relative offset
 * - External syscalls: NOTYPE, UND, st_value == 0 → murmur3 hash of symbol name
 *
 * For external syscalls, the Solana LLVM backend emits CALL instructions with
 * src=1 and imm=-1 as a placeholder. This handler:
 * 1. Computes murmur3_32(symbolName, 0) to get the syscall hash
 * 2. Writes the hash into the IMM field (bytes 4-7)
 * 3. Changes src from 1 to 0 so SLEIGH's "CALL SysCall" pattern matches
 *
 * This creates proper references to the "syscall" address space, enabling
 * Ghidra's analysis to identify and label Solana syscalls.
 *
 * Reference: solana-sbpf/src/elf.rs (relocate function, R_BPF_64_32 case)
 */
public class eBPF_ElfRelocationHandler
		extends AbstractElfRelocationHandler<eBPF_ElfRelocationType, ElfRelocationContext<?>> {

	/** Solana SBF machine type (not yet in ElfConstants) */
	private static final short EM_SBF = 263;

	/** eBPF CALL_IMM opcode (BPF_JMP | BPF_CALL) */
	private static final byte OPCODE_CALL = (byte) 0x85;

	/**
	 * Constructor
	 */
	public eBPF_ElfRelocationHandler() {
		super(eBPF_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		short machine = elf.e_machine();
		return machine == ElfConstants.EM_BPF || machine == EM_SBF;
	}

	@Override
	protected RelocationResult relocate(ElfRelocationContext<?> elfRelocationContext,
			ElfRelocation relocation, eBPF_ElfRelocationType type, Address relocationAddress,
			ElfSymbol symbol, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		Msg.info(this, "[SBF-Reloc] Processing " + type + " at " + relocationAddress +
			" symbol=" + symbolName + " isFunc=" + symbol.isFunction() +
			" isSec=" + symbol.isSection() + " isObj=" + symbol.isObject() +
			" secIdx=" + symbol.getSectionHeaderIndex() + " val=" + symbol.getValue());

		ElfSectionHeader sectionToBeRelocated =
		elfRelocationContext.relocationTable.getSectionToBeRelocated();
		if (sectionToBeRelocated != null &&
				sectionToBeRelocated.getNameAsString().startsWith(".debug")) {
			return RelocationResult.SKIPPED;
		}

		long new_value;
		int byteLength;

		switch (type) {
			case R_BPF_64_64: {
				// Check for unresolved symbol
				if (handleUnresolvedSymbol(elfRelocationContext, relocation, relocationAddress)) {
					return RelocationResult.FAILURE;
				}
				byteLength = 12;
				new_value = symbolAddr.getAddressableWordOffset();
				Byte dst = memory.getByte(relocationAddress.add(0x1));
				memory.setLong(relocationAddress.add(0x4), new_value);
				memory.setByte(relocationAddress.add(0x1), (byte) (dst + 0x10));
				break;
			}
			case R_BPF_64_32: {
				byteLength = 8;

				long instr_next = relocationAddress.add(0x8).getAddressableWordOffset();
				if (symbol.isFunction()) {
					// Check for unresolved symbol
					if (handleUnresolvedSymbol(elfRelocationContext, relocation, relocationAddress)) {
						return RelocationResult.FAILURE;
					}
					// Internal function call: compute PC-relative offset
					new_value = symbolAddr.getAddressableWordOffset();
					int offset = (int) ((new_value - instr_next) / 8);
					memory.setInt(relocationAddress.add(0x4), offset);
				}
				else if (symbol.isSection()) {
					// Check for unresolved symbol
					if (handleUnresolvedSymbol(elfRelocationContext, relocation, relocationAddress)) {
						return RelocationResult.FAILURE;
					}
					// Section-relative call (Linux eBPF convention)
					if (memory.getInt(relocationAddress) == 0x1085) {
						ElfSectionHeader sectionHeader =
							elfRelocationContext.getElfHeader().getSection(symbolName);
						long section_start =
							program.getImageBase().getOffset() + sectionHeader.getAddress();

						int current_imm = memory.getInt(relocationAddress.add(0x4));
						int func_sec_offset = (current_imm + 1) * 8;
						long func_addr = section_start + func_sec_offset;
						int offset = (int) ((func_addr - instr_next) / 8);
						memory.setInt(relocationAddress.add(0x4), offset);
					}
				}
				else if (isExternalSyscall(symbol, symbolName)) {
					// Solana external syscall: undefined NOTYPE symbol
					// The Solana LLVM backend emits src=1, imm=-1 as placeholder.
					// We compute murmur3(symbolName) and rewrite the instruction to
					// src=0, imm=hash so SLEIGH decodes it as "CALL SysCall".
					byte opcode = memory.getByte(relocationAddress);
					Msg.info(this, "[SBF-Reloc] External syscall: " + symbolName +
						" opcode=0x" + Integer.toHexString(opcode & 0xFF) + " at " + relocationAddress);
					if (opcode == OPCODE_CALL) {
						long hash = Murmur3.hash(symbolName.getBytes(StandardCharsets.UTF_8));

						Msg.info(this, "[SBF-Reloc] Writing murmur3 hash 0x" +
							Long.toHexString(hash) + " for " + symbolName);

						// Write murmur3 hash into IMM field (bytes 4-7, little-endian)
						memory.setInt(relocationAddress.add(0x4), (int) hash);

						// Change src from 1 to 0: byte 1 encodes dst[3:0]|src[7:4]
						// src=1 means byte1 = 0x10|dst, src=0 means byte1 = 0x00|dst
						byte srcDst = memory.getByte(relocationAddress.add(0x1));
						byte newSrcDst = (byte) (srcDst & 0x0F); // clear src nibble (set to 0)
						memory.setByte(relocationAddress.add(0x1), newSrcDst);

						Msg.info(this, "[SBF-Reloc] Patched CALL: src " +
							((srcDst >> 4) & 0xF) + " → 0, imm=0x" + Long.toHexString(hash));
					}
				}
				break;
			}
			default: {
				return RelocationResult.UNSUPPORTED;
			}
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

	/**
	 * Check if a symbol represents an external syscall (Solana convention).
	 *
	 * External syscalls in Solana eBPF binaries are:
	 * - NOTYPE (not FUNC, not SECTION, not OBJECT)
	 * - GLOBAL binding
	 * - Undefined (section index = SHN_UNDEF, st_value = 0)
	 *
	 * These include sol_log_, sol_memcpy_, abort, sol_invoke_signed_c, etc.
	 */
	private boolean isExternalSyscall(ElfSymbol symbol, String symbolName) {
		if (symbolName == null || symbolName.isEmpty()) {
			return false;
		}
		// External: section index is SHN_UNDEF (0) and value is 0
		// Type: not function, not section, not object (NOTYPE)
		return !symbol.isFunction() &&
			!symbol.isSection() &&
			!symbol.isObject() &&
			symbol.getSectionHeaderIndex() == 0 &&
			symbol.getValue() == 0;
	}
}
