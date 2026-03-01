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

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Solana syscall analyzer for eBPF programs.
 * 
 * This analyzer identifies Solana syscalls in eBPF bytecode and applies
 * proper function signatures based on the syscall number.
 * 
 * Solana syscall table:
 * 0x0000: invoke
 * 0x0001: invoke_signed  
 * 0x0002: allocate
 * 0x0003: assign
 * 0x0004: return
 * 0x0005: create_account
 * 0x0006: create_account_with_seed
 * 0x0007: close_account
 * 0x0008: invoke_signed_all
 * 0x0009: memmove
 * 0x000A: keccak256
 * 0x000B: sha256
 * 0x000C: ripemd160
 * 0x000D: secp256k1_recover
 * 0x000E: secp256r1_verify
 * 0x000F: ed25519_verify
 * 0x0010: ed25519_prehash_verify
 */
public class SolanaSyscallAnalyzer extends AbstractAnalyzer {
	
	private final static String PROCESSOR_NAME = "eBPF";
	private final static String SYSCALL_ADDRSPACE_NAME = "syscall";

	private final static String NAME = "Solana Syscall Functions";
	private final static String DESCRIPTION = "Apply Solana syscall function signatures to eBPF programs";
	
	// Solana syscall names
	private static final String[] SOLANA_SYSCALL_NAMES = {
		"sol_invoke",
		"sol_invoke_signed",
		"sol_allocate",
		"sol_assign",
		"sol_return",
		"sol_create_account",
		"sol_create_account_with_seed",
		"sol_close_account",
		"sol_invoke_signed_all",
		"sol_memmove",
		"sol_keccak256",
		"sol_sha256",
		"sol_ripemd160",
		"sol_secp256k1_recover",
		"sol_secp256r1_verify",
		"sol_ed25519_verify",
		"sol_ed25519_prehash_verify"
	};
	
	public SolanaSyscallAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.before());
		setDefaultEnablement(true);
	}
	
	@Override
	public boolean canAnalyze(Program program) {
		return PROCESSOR_NAME.equals(program.getLanguage().getProcessor().toString());
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
		
		AddressSetView syscallSet = set.intersectRange(syscallSpace.getMinAddress(), syscallSpace.getMaxAddress());
		if (syscallSet.isEmpty()) {
			return true;
		}
		
		// Clear disassembly errors within syscall space
		BookmarkManager bookmarkMgr = program.getBookmarkManager();
		bookmarkMgr.removeBookmarks(syscallSet, BookmarkType.ERROR, monitor);
		
		SolanaHelperDataTypes helperDataTypes = SolanaHelperDataTypes.get(program, log);
		if (helperDataTypes == null) {
			if (log != null) {
				log.appendMsg("Could not create Solana helper data types");
			}
			return false;
		}
		
		int analyzed = 0;
		for (Function f : program.getFunctionManager().getFunctions(syscallSet, true)) {
			monitor.checkCancelled();
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			
			if (f.getSymbol() != null && f.getSymbol().getSource() != SourceType.DEFAULT) {
				continue;
			}
			
			applySolanaSyscallSignature(f, helperDataTypes, log);
			analyzed++;
		}
		
		if (log != null) {
			log.appendMsg("Analyzed " + analyzed + " Solana syscalls");
		}
		return true;
	}
	
	private void applySolanaSyscallSignature(Function func, SolanaHelperDataTypes helperDataTypes, MessageLog log) {
		int syscallId = (int) func.getEntryPoint().getOffset();
		
		// Check if this is a known Solana syscall
		if (syscallId >= 0 && syscallId < SOLANA_SYSCALL_NAMES.length) {
			try {
				func.setName(SOLANA_SYSCALL_NAMES[syscallId], SourceType.ANALYSIS);
			} catch (DuplicateNameException | InvalidInputException e) {
				if (log != null) {
					log.appendMsg("Could not rename syscall " + syscallId + ": " + e.getMessage());
				}
			}
		}
		
		// Try to apply function signature from data types
		FunctionDefinition syscallDef = helperDataTypes.getSyscallFunctionDef(syscallId);
		
		if (syscallDef != null) {
			try {
				ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
					func.getEntryPoint(), syscallDef, SourceType.ANALYSIS);
				cmd.applyTo(func.getProgram());
			} catch (Exception e) {
				if (log != null) {
					log.appendMsg("Could not apply signature for syscall " + syscallId + ": " + e.getMessage());
				}
			}
		}
	}
}
