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
package ghidra.app.plugin.core.analysis.solana;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Solana syscall analyzer for eBPF programs.
 *
 * Solana eBPF programs use murmur3 hashing to map syscall names to numeric IDs.
 * The CALL instruction's immediate field contains the murmur3 hash of the syscall
 * name (e.g., sol_log_ -> 0x207559bd). This analyzer:
 *
 * 1. Finds functions in the syscall address space
 * 2. Matches their addresses against known Solana syscall murmur3 hashes
 * 3. Renames them and applies proper function signatures
 *
 * Also checks EXTERNAL symbols from the ELF symbol table for sol_* names.
 *
 * Reference: agave/platform-tools-sdk/gen-headers/src/main.rs (murmur3_32 implementation)
 * Reference: agave/syscalls/src/lib.rs (syscall registration)
 */
public class SolanaSyscallAnalyzer extends AbstractAnalyzer {

	private final static String PROCESSOR_NAME = "eBPF";
	private final static String SYSCALL_ADDRSPACE_NAME = "syscall";

	private final static String NAME = "Solana Syscall Functions";
	private final static String DESCRIPTION = "Identify and label Solana syscalls in eBPF programs using murmur3 hash matching";

	/**
	 * Map of murmur3 hash -> Solana syscall name.
	 * Hashes computed using murmur3_32(name.as_bytes(), 0) per agave's gen-headers.
	 *
	 * Complete list of 42 syscalls from agave/syscalls/src/lib.rs
	 * (create_program_runtime_environment_v1).
	 */
	private static final Map<Long, String> SOLANA_SYSCALL_HASHES = new HashMap<>();
	static {
		// Core runtime
		SOLANA_SYSCALL_HASHES.put(0xb6fc1a11L, "abort");
		SOLANA_SYSCALL_HASHES.put(0x686093bbL, "sol_panic_");

		// Logging
		SOLANA_SYSCALL_HASHES.put(0x207559bdL, "sol_log_");
		SOLANA_SYSCALL_HASHES.put(0x5c2a3178L, "sol_log_64_");
		SOLANA_SYSCALL_HASHES.put(0x7ef088caL, "sol_log_pubkey");
		SOLANA_SYSCALL_HASHES.put(0x52ba5096L, "sol_log_compute_units_");
		SOLANA_SYSCALL_HASHES.put(0x7317b434L, "sol_log_data");

		// CPI (Cross-Program Invocation)
		SOLANA_SYSCALL_HASHES.put(0xa22b9c85L, "sol_invoke_signed_c");
		SOLANA_SYSCALL_HASHES.put(0xd7449092L, "sol_invoke_signed_rust");

		// Memory operations
		SOLANA_SYSCALL_HASHES.put(0x717cc4a3L, "sol_memcpy_");
		SOLANA_SYSCALL_HASHES.put(0x434371f8L, "sol_memmove_");
		SOLANA_SYSCALL_HASHES.put(0x3770fb22L, "sol_memset_");
		SOLANA_SYSCALL_HASHES.put(0x5fdcde31L, "sol_memcmp_");

		// Cryptographic hashing
		SOLANA_SYSCALL_HASHES.put(0x11f49d86L, "sol_sha256");
		SOLANA_SYSCALL_HASHES.put(0xd7793abbL, "sol_keccak256");
		SOLANA_SYSCALL_HASHES.put(0x17e40350L, "sol_secp256k1_recover");
		SOLANA_SYSCALL_HASHES.put(0x174c5122L, "sol_blake3");

		// PDA (Program Derived Address)
		SOLANA_SYSCALL_HASHES.put(0x9377323cL, "sol_create_program_address");
		SOLANA_SYSCALL_HASHES.put(0x48504a38L, "sol_try_find_program_address");

		// Sysvar access
		SOLANA_SYSCALL_HASHES.put(0xd56b5fe9L, "sol_get_clock_sysvar");
		SOLANA_SYSCALL_HASHES.put(0xbf7188f6L, "sol_get_rent_sysvar");
		SOLANA_SYSCALL_HASHES.put(0x23a29a61L, "sol_get_epoch_schedule_sysvar");
		SOLANA_SYSCALL_HASHES.put(0x3b97b73cL, "sol_get_fees_sysvar");
		SOLANA_SYSCALL_HASHES.put(0xfdba2b3bL, "sol_get_epoch_rewards_sysvar");
		SOLANA_SYSCALL_HASHES.put(0x188a0031L, "sol_get_last_restart_slot");
		SOLANA_SYSCALL_HASHES.put(0x13c1b505L, "sol_get_sysvar");

		// Program state
		SOLANA_SYSCALL_HASHES.put(0x85532d94L, "sol_get_stack_height");
		SOLANA_SYSCALL_HASHES.put(0xa226d3ebL, "sol_set_return_data");
		SOLANA_SYSCALL_HASHES.put(0x5d2245e4L, "sol_get_return_data");
		SOLANA_SYSCALL_HASHES.put(0xadb8efc8L, "sol_get_processed_sibling_instruction");
		SOLANA_SYSCALL_HASHES.put(0xedef5aeeL, "sol_remaining_compute_units");

		// Curve operations (curve25519 and BLS12-381)
		SOLANA_SYSCALL_HASHES.put(0xaa2607caL, "sol_curve_validate_point");
		SOLANA_SYSCALL_HASHES.put(0xdd1c41a6L, "sol_curve_group_op");
		SOLANA_SYSCALL_HASHES.put(0x60a40880L, "sol_curve_multiscalar_mul");
		SOLANA_SYSCALL_HASHES.put(0x080c98b0L, "sol_curve_decompress");
		SOLANA_SYSCALL_HASHES.put(0xf111a47eL, "sol_curve_pairing_map");

		// Alt_bn128 elliptic curve operations
		SOLANA_SYSCALL_HASHES.put(0xae0c318bL, "sol_alt_bn128_group_op");
		SOLANA_SYSCALL_HASHES.put(0x334fd5edL, "sol_alt_bn128_compression");

		// Big modular exponentiation
		SOLANA_SYSCALL_HASHES.put(0x780e4c15L, "sol_big_mod_exp");

		// Poseidon hash
		SOLANA_SYSCALL_HASHES.put(0xc4947c21L, "sol_poseidon");

		// Epoch stake
		SOLANA_SYSCALL_HASHES.put(0x5be92f4aL, "sol_get_epoch_stake");

		// Memory allocator (deprecated but still present)
		SOLANA_SYSCALL_HASHES.put(0x83f00e8fL, "sol_alloc_free_");
	}

	public SolanaSyscallAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!PROCESSOR_NAME.equals(program.getLanguage().getProcessor().toString())) {
			return false;
		}
		// Quick check: does this binary have any sol_ external symbols?
		// This helps distinguish Solana programs from Linux eBPF programs.
		SymbolIterator extSyms = program.getSymbolTable().getExternalSymbols();
		while (extSyms.hasNext()) {
			Symbol sym = extSyms.next();
			if (sym.getName().startsWith("sol_")) {
				return true;
			}
		}
		// Also check syscall space for known hashes
		AddressSpace syscallSpace = program.getAddressFactory().getAddressSpace(SYSCALL_ADDRSPACE_NAME);
		if (syscallSpace != null) {
			for (Long hash : SOLANA_SYSCALL_HASHES.keySet()) {
				Address addr = syscallSpace.getAddress(hash);
				if (program.getReferenceManager().getReferenceCountTo(addr) > 0) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		AddressSpace syscallSpace = program.getAddressFactory().getAddressSpace(SYSCALL_ADDRSPACE_NAME);
		if (syscallSpace == null) {
			if (log != null) {
				log.appendMsg("Syscall address space not found");
			}
			return false;
		}

		SolanaHelperDataTypes helperDataTypes = SolanaHelperDataTypes.get(program, log);

		int analyzed = 0;

		// Strategy 1: Match functions in syscall space by murmur3 hash
		for (Map.Entry<Long, String> entry : SOLANA_SYSCALL_HASHES.entrySet()) {
			monitor.checkCancelled();

			long hash = entry.getKey();
			String syscallName = entry.getValue();
			Address addr = syscallSpace.getAddress(hash);

			// Check if there are any references to this address
			if (program.getReferenceManager().getReferenceCountTo(addr) > 0) {
				Function func = program.getFunctionManager().getFunctionAt(addr);
				if (func != null) {
					try {
						// Rename from kernel BPF default to Solana name
						if (func.getSymbol().getSource() == SourceType.DEFAULT ||
							func.getName().startsWith("bpf_")) {
							func.setName(syscallName, SourceType.ANALYSIS);
						}
					} catch (DuplicateNameException | InvalidInputException e) {
						if (log != null) {
							log.appendMsg("Could not rename syscall at 0x" +
								Long.toHexString(hash) + ": " + e.getMessage());
						}
					}

					// Apply function signature if we have one
					if (helperDataTypes != null) {
						FunctionDefinition funcDef = helperDataTypes.getSyscallFunctionDef(syscallName);
						if (funcDef != null) {
							ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
								func.getEntryPoint(), funcDef, SourceType.ANALYSIS);
							cmd.applyTo(program);
						}
					}

					analyzed++;
				}
			}
		}

		// Strategy 2: Check EXTERNAL symbols for sol_ names and apply signatures
		SymbolIterator extSyms = program.getSymbolTable().getExternalSymbols();
		while (extSyms.hasNext()) {
			monitor.checkCancelled();
			Symbol sym = extSyms.next();
			String name = sym.getName();
			if (name.startsWith("sol_") || name.equals("abort")) {
				// Apply function signature if available
				if (helperDataTypes != null) {
					FunctionDefinition funcDef = helperDataTypes.getSyscallFunctionDef(name);
					if (funcDef != null) {
						Function func = program.getFunctionManager().getFunctionAt(sym.getAddress());
						if (func != null) {
							ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
								func.getEntryPoint(), funcDef, SourceType.ANALYSIS);
							cmd.applyTo(program);
						}
					}
				}
				analyzed++;
			}
		}

		if (log != null) {
			log.appendMsg("Identified " + analyzed + " Solana syscalls");
		}
		return true;
	}
}
