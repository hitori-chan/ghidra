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

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.data.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;

import java.util.Set;
import java.util.HashSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

/**
 * Advanced Solana function analyzer.
 * Performs deep semantic recovery, type propagation, and RefCell noise folding.
 */
public class SolanaFunctionAnalyzer extends AbstractAnalyzer {

    private final static String PROCESSOR_NAME = "eBPF";
    private final static String NAME = "Solana Function Identification";
    private final static String DESCRIPTION = "Semantic recovery engine for Solana/Rust programs";

    public SolanaFunctionAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
        setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after());
        setDefaultEnablement(true);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {

        int identified = 0;

        identified += identifyPanicHandlers(program, monitor, log);
        identified += identifyErrorFormatter(program, monitor, log);
        identified += identifyEntrypointLogic(program, monitor, log);
        identified += identifyLibraryHelpers(program, monitor, log);
        identified += identifyIteratorHelpers(program, monitor, log);
        identified += identifyVTables(program, monitor, log);
        
        identifySysvarPointers(program, monitor, log);
        annotatePanicLocations(program, monitor, log);
        identifyDiscriminatorsAndHandlers(program, monitor, log);
        
        SolanaPayloadAnalyzer.analyze(program, monitor, log);
        identifyAsyncStateMachines(program, monitor, log);

        // Security Analysis Passes
        annotateSecurityChecks(program, monitor, log);

        // Final Polish Passes
        foldRefCellNoise(program, monitor, log);
        propagateStructureTypes(program, monitor, log);

        if (log != null && identified > 0) {
            log.appendMsg("Solana Decompiler: Identified " + identified + " runtime functions");
        }

        return true;
    }

    // =========================================================================
    // Security Check Annotation Engine
    // =========================================================================

    /**
     * Annotates security-relevant patterns in all functions.
     *
     * For each function that accesses accounts (via RustAccountInfo or SolAccountInfo offsets),
     * detects:
     * - Signer checks (reading is_signer field + conditional branch)
     * - Owner checks (sol_memcmp_ on owner field + conditional branch)
     * - PDA validation (sol_try_find_program_address + comparison)
     * - Lamports mutations (writes to lamports field)
     * - CPI calls (sol_invoke_signed_c/rust) and whether program_id is validated
     *
     * Results are added as plate comments on the function, making them immediately
     * visible in decompiled output for the LLM investigator.
     */
    private void annotateSecurityChecks(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException {
        int annotated = 0;

        for (Function f : program.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (f.isThunk() || f.getBody().getNumAddresses() < 16) continue;

            SecurityProfile profile = analyzeSecurityProfile(program, f, monitor);
            if (profile.isEmpty()) continue;

            String annotation = profile.toAnnotation();
            if (annotation != null && !annotation.isEmpty()) {
                String existing = f.getComment();
                if (existing != null && existing.contains("SECURITY")) continue; // already annotated
                String combined = (existing != null ? existing + "\n" : "") + annotation;
                f.setComment(combined);
                annotated++;
            }
        }

        if (log != null && annotated > 0) {
            log.appendMsg("Solana Security: Annotated " + annotated + " functions with security profiles");
        }
    }

    /**
     * Analyzes a single function for security-relevant patterns.
     */
    private SecurityProfile analyzeSecurityProfile(Program program, Function f, TaskMonitor monitor) throws CancelledException {
        SecurityProfile profile = new SecurityProfile();
        Set<Function> calledFunctions = f.getCalledFunctions(monitor);

        // Collect called function names for quick lookup
        Set<String> calledNames = new HashSet<>();
        for (Function called : calledFunctions) {
            calledNames.add(called.getName());
        }

        // Track CPI presence
        if (calledNames.contains("sol_invoke_signed_c") || calledNames.contains("sol_invoke_signed_rust") ||
            calledNames.contains("sol_lib_invoke") || calledNames.contains("sol_lib_invoke_signed")) {
            profile.hasCPI = true;
        }

        // Track PDA operations
        if (calledNames.contains("sol_create_program_address") || calledNames.contains("sol_try_find_program_address")) {
            profile.hasPDADerivation = true;
        }

        // Track sysvar access
        if (calledNames.contains("sol_get_clock_sysvar") || calledNames.contains("sol_lib_get_clock")) {
            profile.accessesClock = true;
        }

        // Scan instructions for field-level access patterns
        InstructionIterator iter = program.getListing().getInstructions(f.getBody(), true);

        while (iter.hasNext()) {
            Instruction inst = iter.next();
            String mnem = inst.getMnemonicString().toLowerCase();

            // Check for sol_memcmp_ calls (owner check pattern)
            if (mnem.startsWith("call")) {
                Address target = getCallTarget(inst);
                if (target != null) {
                    Function called = program.getFunctionManager().getFunctionAt(target);
                    if (called != null) {
                        if (called.getName().equals("sol_memcmp_")) {
                            if (isNearOwnerFieldAccess(program, inst, 15)) {
                                profile.ownerChecks++;
                                inst.setComment(CodeUnit.EOL_COMMENT, "SECURITY: owner comparison (sol_memcmp_)");
                            }
                        }
                    }
                }
            }

            // Detect account field access patterns via load instructions
            // LDX has 3 operands: op[0]=dst_reg, op[1]=base_reg, op[2]=offset_scalar
            if (mnem.startsWith("ldx") && inst.getNumOperands() >= 3) {
                Object[] ops2 = inst.getOpObjects(2);
                if (ops2.length >= 1 && ops2[0] instanceof Scalar) {
                    long offset = ((Scalar) ops2[0]).getSignedValue();
                    int width = SolanaPayloadAnalyzer.getWidth(mnem);

                    // ── RustAccountInfo offsets (48-byte struct) ──
                    // Disambiguate from serialized buffer: Rust boolean fields are
                    // always 1-byte loads (LDXB). Offset 40 with a wider load is NOT
                    // is_signer — it's likely a serialized buffer owner access (0x28=40).
                    if (offset == 40 && width == 1) {  // LDXB only — Rust is_signer
                        profile.signerFieldReads++;
                        if (isFollowedByConditionalBranch(inst, 4)) {
                            profile.signerChecks++;
                            inst.setComment(CodeUnit.EOL_COMMENT, "SECURITY: is_signer check (RustAccountInfo+0x28)");
                        } else {
                            inst.setComment(CodeUnit.EOL_COMMENT, "SECURITY: is_signer read (NO branch follows!)");
                        }
                    }
                    else if (offset == 41 && width == 1) {  // LDXB — Rust is_writable
                        profile.writableFieldReads++;
                        if (isFollowedByConditionalBranch(inst, 4)) {
                            profile.writableChecks++;
                            inst.setComment(CodeUnit.EOL_COMMENT, "SECURITY: is_writable check (RustAccountInfo+0x29)");
                        }
                    }

                    // ── Owner pointer loads ──
                    // RustAccountInfo +24 = owner_ptr (8-byte pointer load)
                    if (offset == 24 && width == 8) {
                        profile.ownerFieldReads++;
                        inst.setComment(CodeUnit.EOL_COMMENT, "SECURITY: owner_ptr load (RustAccountInfo+0x18)");
                    }

                    // ── Serialized buffer offsets (C ABI) ──
                    // is_signer at +0x01, is_writable at +0x02 — always byte loads
                    if (offset == 0x01 && width == 1) {
                        profile.signerFieldReads++;
                        if (isFollowedByConditionalBranch(inst, 4)) {
                            profile.signerChecks++;
                            inst.setComment(CodeUnit.EOL_COMMENT, "SECURITY: is_signer check (serialized +0x01)");
                        }
                    }
                    else if (offset == 0x02 && width == 1) {
                        profile.writableFieldReads++;
                        if (isFollowedByConditionalBranch(inst, 4)) {
                            profile.writableChecks++;
                            inst.setComment(CodeUnit.EOL_COMMENT, "SECURITY: is_writable check (serialized +0x02)");
                        }
                    }
                }
            }

            // Detect lamports and data_len writes
            // STX has 3 operands: op[0]=base_reg, op[1]=offset_scalar, op[2]=src_reg
            if (mnem.startsWith("stx") && inst.getNumOperands() >= 3) {
                Object[] stxOps1 = inst.getOpObjects(1);
                if (stxOps1.length >= 1 && stxOps1[0] instanceof Scalar) {
                    long offset = ((Scalar) stxOps1[0]).getSignedValue();
                    if (offset == 0x48) {
                        profile.lamportsWrites++;
                        inst.setComment(CodeUnit.EOL_COMMENT, "SECURITY: lamports write (serialized +0x48)");
                    } else if (offset == 0x50) {
                        profile.dataLenWrites++;
                        inst.setComment(CodeUnit.EOL_COMMENT, "SECURITY: data_len write (serialized +0x50)");
                    }
                }
            }
        }

        return profile;
    }

    /**
     * Checks if an instruction is followed by a conditional branch within N instructions.
     * Stops scanning at EXIT or CALL boundaries.
     */
    private boolean isFollowedByConditionalBranch(Instruction inst, int lookahead) {
        Instruction next = inst.getNext();
        for (int i = 0; i < lookahead && next != null; i++) {
            String mnem = next.getMnemonicString().toLowerCase();
            if (mnem.startsWith("j") && !mnem.equals("ja") && !mnem.equals("jmp")) {
                return true;
            }
            if (mnem.equals("exit") || mnem.startsWith("call")) break;
            next = next.getNext();
        }
        return false;
    }

    /**
     * Checks if a sol_memcmp_ call is near a load from the owner field offset.
     * Looks back up to `lookback` instructions for owner-related offsets.
     */
    private boolean isNearOwnerFieldAccess(Program program, Instruction callInst, int lookback) {
        Instruction prev = callInst.getPrevious();
        for (int i = 0; i < lookback && prev != null; i++) {
            String mnem = prev.getMnemonicString().toLowerCase();
            if (mnem.startsWith("ldx") && prev.getNumOperands() >= 3) {
                // LDX: op[2] = offset scalar
                Object[] ops = prev.getOpObjects(2);
                if (ops.length >= 1 && ops[0] instanceof Scalar) {
                    long offset = ((Scalar) ops[0]).getSignedValue();
                    if (offset == 24 || offset == 0x28) return true;
                }
            } else if (mnem.startsWith("add")) {
                // ADD: op[1] = immediate scalar
                Object[] ops = prev.getOpObjects(1);
                if (ops.length >= 1 && ops[0] instanceof Scalar) {
                    long offset = ((Scalar) ops[0]).getSignedValue();
                    if (offset == 24 || offset == 0x28) return true;
                }
            }
            prev = prev.getPrevious();
        }
        return false;
    }

    /**
     * Security profile for a single function. Tracks what security checks are present/absent.
     */
    private static class SecurityProfile {
        int signerFieldReads = 0;
        int signerChecks = 0;
        int ownerChecks = 0;
        int ownerFieldReads = 0;
        int writableFieldReads = 0;
        int writableChecks = 0;
        int lamportsWrites = 0;
        int dataLenWrites = 0;
        boolean hasCPI = false;
        boolean hasPDADerivation = false;
        boolean accessesClock = false;

        boolean isEmpty() {
            return signerFieldReads == 0 && ownerChecks == 0 && ownerFieldReads == 0
                && writableFieldReads == 0 && lamportsWrites == 0 && dataLenWrites == 0
                && !hasCPI && !hasPDADerivation;
        }

        String toAnnotation() {
            StringBuilder sb = new StringBuilder();
            sb.append("[SECURITY PROFILE]\n");

            if (hasCPI) {
                sb.append("  CPI: YES (cross-program invocation present)\n");
                if (ownerChecks == 0 && ownerFieldReads == 0) {
                    sb.append("  WARNING: CPI without owner validation detected\n");
                }
            }

            if (hasPDADerivation) {
                sb.append("  PDA: YES (program derived address computation)\n");
            }

            if (signerFieldReads > 0) {
                sb.append("  Signer: ").append(signerChecks).append(" check(s) from ")
                    .append(signerFieldReads).append(" read(s)\n");
                if (signerChecks < signerFieldReads) {
                    sb.append("  WARNING: is_signer read without branch — possible missing signer check\n");
                }
            } else if (hasCPI || lamportsWrites > 0) {
                sb.append("  WARNING: No is_signer reads in function that modifies state\n");
            }

            if (writableFieldReads > 0) {
                sb.append("  Writable: ").append(writableChecks).append(" check(s) from ")
                    .append(writableFieldReads).append(" read(s)\n");
            }

            if (ownerChecks > 0) {
                sb.append("  Owner: ").append(ownerChecks).append(" validation(s) via sol_memcmp_\n");
            } else if (ownerFieldReads > 0) {
                sb.append("  Owner: ").append(ownerFieldReads).append(" field read(s), no memcmp validation\n");
            } else if (hasCPI) {
                sb.append("  WARNING: No owner validation in function with CPI\n");
            }

            if (lamportsWrites > 0) {
                sb.append("  Lamports: ").append(lamportsWrites).append(" write(s) detected\n");
            }

            if (dataLenWrites > 0) {
                sb.append("  DataLen: ").append(dataLenWrites).append(" write(s) detected\n");
            }

            if (accessesClock) {
                sb.append("  Sysvar: Clock access present\n");
            }

            return sb.toString();
        }
    }

    /**
     * Identifies the 5-instruction RefCell/Rc decrement pattern and adds semantic comments.
     */
    private void foldRefCellNoise(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException {
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            InstructionIterator iter = program.getListing().getInstructions(f.getBody(), true);
            while (iter.hasNext()) {
                Instruction inst = iter.next();
                // Pattern: load count, subtract 1, store count, check if zero
                String mnem = inst.getMnemonicString().toLowerCase();
                if (mnem.startsWith("ldx") && isRefCellAccess(inst)) {
                    Instruction next = inst.getNext();
                    if (next != null && next.getMnemonicString().equals("add") && isDecrementOne(next)) {
                        Instruction store = next.getNext();
                        if (store != null && store.getMnemonicString().startsWith("stx")) {
                            inst.setComment(CodeUnit.EOL_COMMENT, "// DROP(AccountInfo resource)");
                        }
                    }
                }
            }
        }
    }

    private boolean isRefCellAccess(Instruction inst) {
        // RefCell strong count is at offset 0 of the Rc<RefCell> struct.
        // LDX has 3 operands: op[2] = offset scalar
        if (inst.getNumOperands() < 3) return false;
        Object[] ops = inst.getOpObjects(2);
        if (ops.length >= 1 && ops[0] instanceof Scalar) {
            long off = ((Scalar)ops[0]).getSignedValue();
            if (off != 0) return false;
            return inst.getMnemonicString().toLowerCase().endsWith("dw");
        }
        return false;
    }

    private boolean isDecrementOne(Instruction inst) {
        // ADD has 2 operands: op[1] = immediate scalar
        if (inst.getNumOperands() < 2) return false;
        Object[] ops = inst.getOpObjects(1);
        return ops.length >= 1 && ops[0] instanceof Scalar && ((Scalar)ops[0]).getSignedValue() == -1;
    }

    /**
     * Propagates structure types from parameters to local assignments.
     */
    private void propagateStructureTypes(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException {
        DataType aiBase = program.getDataTypeManager().getDataType("/RustAccountInfo");
        if (aiBase == null) return;
        DataType aiPtr = new PointerDataType(aiBase);

        for (Function f : program.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            // If function takes a SolPubkey* (the return buffer) or RustAccountInfo*, propagate
            for (Parameter p : f.getParameters()) {
                if (p.getDataType().getName().contains("AccountInfo")) {
                    applyTypeToDerivativeLocals(f, p, aiPtr);
                }
            }
        }
    }

    private void applyTypeToDerivativeLocals(Function f, Parameter p, DataType type) {
        // Logic to track register/stack moves of the parameter and apply the type
        // For now, we apply it to local variables that share name similarities or offsets
        for (Variable v : f.getLocalVariables()) {
            if (v.getName().contains("pRVar") || v.getName().contains("pRStack")) {
                try { v.setDataType(type, SourceType.ANALYSIS); } catch (Exception e) {}
            }
        }
    }

    private void identifyAsyncStateMachines(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException {
        // Async state machines (flattened Future::poll) have specific characteristics:
        // - Very large (>1500 bytes)
        // - Many conditional branches (>50)
        // - Do NOT call handler_disc_ functions (real dispatchers do)
        // - Are NOT themselves handlers (not called from dispatch blocks)
        //
        // Previous threshold was too aggressive (>500 bytes, >20 jumps) which misnamed
        // real handler functions that happened to be large.
        int found = 0;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (!f.getName().startsWith("FUN_")) continue;
            if (f.getBody().getNumAddresses() < 1500) continue;

            // Check that none of its callees are handler_disc_ functions
            boolean callsHandler = false;
            for (Function called : f.getCalledFunctions(monitor)) {
                if (called.getName().startsWith("handler_disc_")) {
                    callsHandler = true;
                    break;
                }
            }
            if (callsHandler) continue;

            // Count conditional jumps — async state machines have very high branch density
            int jumpCount = 0;
            InstructionIterator iter = program.getListing().getInstructions(f.getBody(), true);
            while (iter.hasNext()) {
                String mnem = iter.next().getMnemonicString().toLowerCase();
                if (mnem.startsWith("j") && !mnem.equals("ja")) jumpCount++;
            }
            if (jumpCount > 50) {
                try {
                    f.setName("async_poll_state_machine_" + f.getEntryPoint().toString(), SourceType.ANALYSIS);
                } catch (Exception e) {
                    Msg.error(this, "Error naming async state machine at " + f.getEntryPoint(), e);
                }
                f.setComment("Possible flattened Async State Machine (Future::poll)");
                found++;
            }
        }
        if (found > 0 && log != null) log.appendMsg("Identified " + found + " async state machines");
    }

    private void identifyDiscriminatorsAndHandlers(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException {
        Function entry = null;
        for (Symbol sym : program.getSymbolTable().getSymbols("entrypoint")) {
            if (sym.getSymbolType() == ghidra.program.model.symbol.SymbolType.FUNCTION) {
                entry = program.getFunctionManager().getFunctionAt(sym.getAddress());
                break;
            }
        }
        if (entry != null) analyzeDispatcher(program, entry, log);
        for (Symbol sym : program.getSymbolTable().getSymbols("process_instruction")) {
            if (sym.getSymbolType() == ghidra.program.model.symbol.SymbolType.FUNCTION) {
                Function pi = program.getFunctionManager().getFunctionAt(sym.getAddress());
                if (pi != null && !pi.equals(entry)) analyzeDispatcher(program, pi, log);
            }
        }
    }

    private void analyzeDispatcher(Program program, Function pi, MessageLog log) {
        // Strategy: Solana dispatch uses jeq/jne to compare the first byte of
        // instruction_data against discriminator constants, then jumps to handler code
        // that calls the handler function. We need to:
        // 1. Collect discriminator values from jeq/jne comparisons
        // 2. Follow the branch targets to find the actual handler calls
        //
        // We also handle the simpler case where a mov/comparison + call happens linearly.

        Map<Long, Address> discToTarget = new HashMap<>();

        // Pass 1: Collect discriminator-to-jump-target mappings from conditional branches
        InstructionIterator iter = program.getListing().getInstructions(pi.getBody(), true);
        while (iter.hasNext()) {
            Instruction inst = iter.next();
            String mnem = inst.getMnemonicString().toLowerCase();

            if (mnem.startsWith("jeq") || mnem.startsWith("jne")) {
                long discVal = -1;
                for (int i = 0; i < inst.getNumOperands(); i++) {
                    Scalar s = inst.getScalar(i);
                    if (s != null) {
                        long val = s.getUnsignedValue();
                        // Discriminators are typically 0-255 (single byte) or Anchor 8-byte hashes
                        if (val > 0 && val <= 0xFF) {
                            discVal = val;
                        }
                    }
                }
                if (discVal != -1) {
                    // For jeq, the branch target is the handler block
                    Address[] flows = inst.getFlows();
                    Instruction nextInst = inst.getNext();
                    for (Address flowTarget : flows) {
                        if (nextInst == null || !flowTarget.equals(nextInst.getAddress())) {
                            discToTarget.put(discVal, flowTarget);
                        }
                    }
                }
            }
        }

        // Pass 2: For each branch target, find the first call in the block and rename it
        for (Map.Entry<Long, Address> entry : discToTarget.entrySet()) {
            long disc = entry.getKey();
            Address blockAddr = entry.getValue();

            // Scan forward from the branch target to find the first call
            Instruction inst = program.getListing().getInstructionAt(blockAddr);
            for (int i = 0; i < 20 && inst != null; i++) {
                String mnem = inst.getMnemonicString().toLowerCase();
                if (mnem.startsWith("call")) {
                    Address target = getCallTarget(inst);
                    if (target != null && target.isMemoryAddress()) {
                        Function f = program.getFunctionManager().getFunctionAt(target);
                        if (f != null && f.getName().startsWith("FUN_") && !f.isThunk()) {
                            String suffix = String.valueOf(disc);
                            renameAndTypeAs(f, "handler_disc_" + suffix, "process_instruction", log);
                            inst.setComment(CodeUnit.EOL_COMMENT, "Instruction Handler for discriminator " + suffix);
                        }
                    }
                    break;
                }
                if (mnem.equals("exit") || mnem.equals("ret")) break;
                inst = inst.getNext();
            }
        }

    }

    private int identifyVTables(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException {
        int found = 0;
        ghidra.program.model.mem.Memory mem = program.getMemory();
        AddressSpace ram = program.getAddressFactory().getDefaultAddressSpace();
        for (ghidra.program.model.mem.MemoryBlock block : mem.getBlocks()) {
            if (!block.getName().contains("rodata") && !block.getName().contains("data.rel.ro")) continue;
            Address addr = block.getStart();
            while (addr.compareTo(block.getEnd()) < 0) {
                monitor.checkCancelled();
                try {
                    long val = mem.getLong(addr);
                    if (val > 0 && val < 0x1000000 && val % 8 == 0) {
                        Address target = ram.getAddress(val);
                        Function f = program.getFunctionManager().getFunctionAt(target);
                        if (f != null && isFunctionPointerArray(program, addr, 3)) {
                            markVTable(program, addr, log);
                            found++;
                            addr = addr.add(24);
                            continue;
                        }
                    }
                } catch (Exception e) {}
                addr = addr.add(8);
            }
        }
        return found;
    }

    private boolean isFunctionPointerArray(Program program, Address addr, int minCount) {
        try {
            for (int i = 0; i < minCount; i++) {
                long val = program.getMemory().getLong(addr.add(i * 8));
                Address target = program.getAddressFactory().getDefaultAddressSpace().getAddress(val);
                if (program.getFunctionManager().getFunctionAt(target) == null) return false;
            }
            return true;
        } catch (Exception e) { return false; }
    }

    private void markVTable(Program program, Address addr, MessageLog log) {
        try {
            program.getSymbolTable().createLabel(addr, "VTABLE_" + addr, SourceType.ANALYSIS);
            for (int i = 0; i < 8; i++) {
                long val = program.getMemory().getLong(addr.add(i * 8));
                Address target = program.getAddressFactory().getDefaultAddressSpace().getAddress(val);
                Function f = program.getFunctionManager().getFunctionAt(target);
                if (f != null && f.getName().startsWith("FUN_")) {
                    f.setName("vfunc_" + addr + "_" + i, SourceType.ANALYSIS);
                } else if (f == null) break;
            }
        } catch (Exception e) {
            if (log != null) log.appendMsg("Error marking VTable at " + addr + ": " + e.getMessage());
        }
    }

    private Address getCallTarget(Instruction inst) {
        Reference[] refs = inst.getReferencesFrom();
        if (refs.length > 0) return refs[0].getToAddress();
        Address[] flows = inst.getFlows();
        if (flows.length > 0) return flows[0];
        return null;
    }

    private void identifySysvarPointers(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException {
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            InstructionIterator iter = program.getListing().getInstructions(f.getBody(), true);
            while (iter.hasNext()) {
                Instruction inst = iter.next();
                if (inst.getMnemonicString().equalsIgnoreCase("call")) {
                    Address target = getCallTarget(inst);
                    if (target == null) continue;
                    Function called = program.getFunctionManager().getFunctionAt(target);
                    if (called == null) continue;
                    String typeName = null;
                    if (called.getName().equals("sol_lib_get_clock")) typeName = "/SolClock";
                    else if (called.getName().equals("sol_lib_get_rent")) typeName = "/SolRent";
                    if (typeName != null) {
                        DataType dt = program.getDataTypeManager().getDataType(typeName);
                        if (dt != null) inst.setComment(CodeUnit.PRE_COMMENT, "Buffer typed as " + dt.getName());
                    }
                }
            }
        }
    }

    private void annotatePanicLocations(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException {
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            InstructionIterator iter = program.getListing().getInstructions(f.getBody(), true);
            while (iter.hasNext()) {
                Instruction inst = iter.next();
                if (inst.getMnemonicString().equalsIgnoreCase("call")) {
                    Address target = getCallTarget(inst);
                    if (target == null) continue;
                    Function called = program.getFunctionManager().getFunctionAt(target);
                    if (called != null && called.getName().equals("sol_panic_")) {
                        String file = findConstantString(program, inst.getAddress());
                        if (file != null) f.setComment("Original Source: " + file);
                    }
                }
            }
        }
    }

    private String findConstantString(Program program, Address addr) {
        Instruction inst = program.getListing().getInstructionAt(addr);
        if (inst == null) return null;
        for (int i = 0; i < 15; i++) {
            inst = inst.getPrevious();
            if (inst == null) break;
            Reference[] refs = inst.getReferencesFrom();
            for (Reference ref : refs) {
                Address toAddr = ref.getToAddress();
                if (toAddr.isMemoryAddress()) {
                    ghidra.program.model.mem.MemoryBlock block = program.getMemory().getBlock(toAddr);
                    if (block != null && (block.getName().contains("rodata") || block.getName().contains("data"))) {
                        String s = getStringAt(program, toAddr);
                        if (s != null && s.length() > 2) return s;
                    }
                }
            }
        }
        return null;
    }

    private String getStringAt(Program program, Address addr) {
        try {
            byte[] bytes = new byte[128];
            program.getMemory().getBytes(addr, bytes);
            int len = 0;
            while (len < bytes.length && bytes[len] != 0) len++;
            return new String(bytes, 0, len);
        } catch (Exception e) { return null; }
    }

    private int identifyLibraryHelpers(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException {
        int found = 0;
        Function allocSyscall = null;
        Function invokeSignedRust = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals("sol_alloc_free_")) allocSyscall = f;
            if (f.getName().equals("sol_invoke_signed_rust")) invokeSignedRust = f;
        }
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (!f.getName().startsWith("FUN_")) continue;
            Set<Function> called = f.getCalledFunctions(monitor);
            if (allocSyscall != null && called.contains(allocSyscall)) {
                if (f.getBody().getNumAddresses() < 100) {
                    renameAndType(f, "sol_lib_alloc", log);
                    found++;
                    continue;
                }
            }
            if (called.size() == 1) {
                Function c = called.iterator().next();
                if (c.getName().equals("sol_get_clock_sysvar")) { renameAndType(f, "sol_lib_get_clock", log); found++; }
                else if (c.getName().equals("sol_get_rent_sysvar")) { renameAndType(f, "sol_lib_get_rent", log); found++; }
            }
            if (invokeSignedRust != null && called.contains(invokeSignedRust)) {
                renameAndType(f, "sol_lib_invoke_signed", log);
                found++;
            }
        }
        Function libInvokeSigned = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals("sol_lib_invoke_signed")) { libInvokeSigned = f; break; }
        }
        if (libInvokeSigned != null) {
            for (Function f : program.getFunctionManager().getFunctions(true)) {
                if (!f.getName().startsWith("FUN_")) continue;
                if (f.getCalledFunctions(monitor).contains(libInvokeSigned)) {
                    renameAndType(f, "sol_lib_invoke", log);
                    found++;
                }
            }
        }
        return found;
    }

    private int identifyErrorFormatter(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException {
        int found = 0;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (!f.getName().startsWith("FUN_")) continue;
            boolean hasXorConst = false;
            boolean hasMapConst = false;
            InstructionIterator iter = program.getListing().getInstructions(f.getBody(), true);
            while (iter.hasNext()) {
                Instruction inst = iter.next();
                for (int i = 0; i < inst.getNumOperands(); i++) {
                    Scalar scalar = inst.getScalar(i);
                    if (scalar != null) {
                        long val = scalar.getValue();
                        if (val == 0x8000000000000000L) hasXorConst = true;
                        if (val == 0x100000000L || val == 0x200000000L) hasMapConst = true;
                    }
                }
            }
            if (hasXorConst && hasMapConst) {
                renameAndType(f, "program_error_into_u64", log);
                found++;
            }
        }
        return found;
    }

    private int identifyEntrypointLogic(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException {
        Function entrypoint = null;
        for (Symbol sym : program.getSymbolTable().getSymbols("entrypoint")) {
            if (sym.getSymbolType() == ghidra.program.model.symbol.SymbolType.FUNCTION) {
                entrypoint = program.getFunctionManager().getFunctionAt(sym.getAddress());
                break;
            }
        }
        if (entrypoint == null) return 0;
        
        try {
            Variable[] locals = entrypoint.getLocalVariables();
            for (Variable var : locals) {
                if (var.isStackVariable()) {
                    int offset = var.getStackOffset();
                    if (offset == -0x40) var.setName("accounts_ptr", SourceType.ANALYSIS);
                    else if (offset == -0x38) var.setName("accounts_len", SourceType.ANALYSIS);
                    else if (offset == -0x28) var.setName("data_ptr", SourceType.ANALYSIS);
                    else if (offset == -0x20) var.setName("data_len", SourceType.ANALYSIS);
                    else if (offset == -0x18) var.setName("program_id_ptr", SourceType.ANALYSIS);
                }
            }
        } catch (Exception e) {
            if (log != null) log.appendMsg("Error naming entrypoint variables: " + e.getMessage());
        }

        List<Function> calls = new ArrayList<>();
        InstructionIterator instIter = program.getListing().getInstructions(entrypoint.getBody(), true);
        while (instIter.hasNext()) {
            Instruction inst = instIter.next();
            if (inst.getMnemonicString().equalsIgnoreCase("call")) {
                Address target = getCallTarget(inst);
                if (target != null && target.isMemoryAddress()) {
                    Function f = program.getFunctionManager().getFunctionAt(target);
                    if (f != null && !f.isThunk() && !calls.contains(f)) calls.add(f);
                }
            }
        }

        int found = 0;
        if (calls.size() >= 1) { renameAndType(calls.get(0), "sol_deserialize", log); found++; }
        if (calls.size() >= 2) {
            Function second = calls.get(1);
            // Only rename to process_instruction if:
            // 1. Still has default name (FUN_)
            // 2. Large enough to be a real handler (not a helper)
            // 3. Only called once (from entrypoint — a process_instruction is the main dispatcher)
            if (second.getName().startsWith("FUN_") && second.getBody().getNumAddresses() > 100
                && program.getReferenceManager().getReferenceCountTo(second.getEntryPoint()) <= 2) {
                renameAndType(second, "process_instruction", log);
                found++;
            }
        }
        return found;
    }

    private int identifyIteratorHelpers(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException {
        int found = 0;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (!f.getName().startsWith("FUN_")) continue;
            // next_account_info is small, called multiple times, panics on bounds check,
            // and has a comparison + conditional branch pattern before the panic call.
            if (f.getBody().getNumAddresses() > 200 || f.getBody().getNumAddresses() < 16) continue;
            if (program.getReferenceManager().getReferenceCountTo(f.getEntryPoint()) < 2) continue;

            boolean callsPanic = false;
            boolean hasCompareAndBranch = false;
            for (Function sub : f.getCalledFunctions(monitor)) {
                if (sub.getName().equals("sol_panic") || sub.getName().equals("abort")) {
                    callsPanic = true;
                    break;
                }
            }
            if (!callsPanic) continue;

            // Require a comparison pattern: load + conditional branch (bounds check)
            InstructionIterator iter = program.getListing().getInstructions(f.getBody(), true);
            while (iter.hasNext()) {
                Instruction inst = iter.next();
                String mnem = inst.getMnemonicString().toLowerCase();
                // Look for conditional jumps comparing two registers (jge, jlt, etc.)
                if ((mnem.startsWith("jge") || mnem.startsWith("jlt") || mnem.startsWith("jle") || mnem.startsWith("jgt"))
                    && !mnem.endsWith("32")) {
                    hasCompareAndBranch = true;
                    break;
                }
            }

            if (hasCompareAndBranch) {
                renameAndType(f, "next_account_info", log);
                found++;
            }
        }
        return found;
    }

    private int identifyPanicHandlers(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException {
        int found = 0;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (!f.getName().startsWith("FUN_")) continue;
            boolean callsLog = false;
            boolean callsAbort = false;
            for (Function called : f.getCalledFunctions(monitor)) {
                if (called.getName().equals("sol_log_")) callsLog = true;
                if (called.getName().equals("abort")) callsAbort = true;
            }
            if (callsLog && callsAbort) { renameAndType(f, "sol_panic", log); found++; }
        }
        return found;
    }

    private void renameAndType(Function f, String newName, MessageLog log) {
        renameAndTypeAs(f, newName, newName, log);
    }

    private void renameAndTypeAs(Function f, String newName, String typeName, MessageLog log) {
        try {
            f.setName(newName, SourceType.ANALYSIS);
            SolanaHelperDataTypes helper = SolanaHelperDataTypes.get(f.getProgram(), log);
            if (helper != null) {
                FunctionDefinition funcDef = helper.getSyscallFunctionDef(typeName);
                if (funcDef != null) {
                    ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                        new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(f.getEntryPoint(), funcDef, SourceType.ANALYSIS);
                    cmd.applyTo(f.getProgram());
                }
            }
        } catch (Exception e) {
            if (log != null) log.appendMsg("Error naming/typing function " + f.getName() + ": " + e.getMessage());
        }
    }

    @Override
    public boolean canAnalyze(Program program) {
        return PROCESSOR_NAME.equals(program.getLanguage().getProcessor().toString());
    }
}
