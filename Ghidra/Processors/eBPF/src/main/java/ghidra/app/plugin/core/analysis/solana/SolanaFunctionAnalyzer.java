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
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.data.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;

import java.util.Set;
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
        identifyHandlerImplementationCallees(program, monitor, log);
        
        SolanaPayloadAnalyzer.analyze(program, monitor, log);
        identifyAsyncStateMachines(program, monitor, log);

        // Final Polish Passes
        foldRefCellNoise(program, monitor, log);
        propagateStructureTypes(program, monitor, log);

        if (log != null && identified > 0) {
            log.appendMsg("Solana Decompiler: Identified " + identified + " runtime functions");
        }

        return true;
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
        // Do NOT analyze `entrypoint` as a dispatcher: it is macro boilerplate
        // (deserialize -> call -> Rc-drop), and its `if (refcount == 0)` drop checks
        // compile to `jeq R, 0x0`, which the discriminator scan misreads as
        // "dispatch case 0" and mislabels the drop/free callee as handler_disc_0
        // (force-typing it as process_instruction). The real `match instruction_data[0]`
        // dispatch lives in process_instruction (the renamed deserialize callee).
        for (Symbol sym : program.getSymbolTable().getSymbols("process_instruction")) {
            if (sym.getSymbolType() == ghidra.program.model.symbol.SymbolType.FUNCTION) {
                Function pi = program.getFunctionManager().getFunctionAt(sym.getAddress());
                if (pi != null && !pi.equals(entry)) analyzeDispatcher(program, pi, log);
            }
        }
    }

    private void analyzeDispatcher(Program program, Function pi, MessageLog log) {
        // Strategy: Solana dispatch often routes through small case IDs even for
        // Anchor programs that originally use 8-byte discriminators. The case ID
        // is still useful for naming/role recovery, but should be treated as a
        // synthetic dispatch label rather than the raw on-wire discriminator.
        //
        // We need to:
        // 1. Collect discriminator values from jeq/jne comparisons
        // 2. Follow the branch targets to find the actual handler calls
        //
        // We also handle the simpler case where a mov/comparison + call happens linearly.

        // Pass 1: bucket (caseValue -> branchTarget) by the COMPARED REGISTER. Only the
        // register holding the discriminator byte drives the real dispatch; the function
        // is also full of unrelated `jeq R, 0`-style guards (account-count checks, null /
        // zero / RefCell-borrow tests) on other registers. Mixing those in fabricates
        // phantom handlers — most often a `handler_disc_0` that is really a memset/drop
        // helper reached from some zero-check's target block.
        Map<String, Map<Long, Address>> byReg = new HashMap<>();
        Map<String, Address> firstSeen = new HashMap<>();
        // Track `lddw Rx, CONST` so Anchor's 8-byte discriminator dispatch is recognized:
        // Anchor loads each instruction's sha256-derived discriminator into a temp register
        // and does `jeq/jne R_disc, Rtmp` (register-vs-register), which has no scalar operand
        // to read. Resolving the temp register back to its loaded constant lets the same
        // dispatch machinery name Anchor handlers, not just native byte-discriminator ones.
        Map<String, Long> lddwVals = new HashMap<>();
        InstructionIterator iter = program.getListing().getInstructions(pi.getBody(), true);
        while (iter.hasNext()) {
            Instruction inst = iter.next();
            String mnem = inst.getMnemonicString().toLowerCase();

            if (mnem.startsWith("lddw")) {
                String dst = registerOperand(inst, 0);
                if (dst != null) {
                    Long c = firstScalar(inst);
                    if (c != null) lddwVals.put(dst, c);
                }
                continue;
            }

            if (mnem.startsWith("jeq") || mnem.startsWith("jne")) {
                String reg = getBranchCompareRegister(inst);     // operand 0 = discriminator reg
                Long discVal = getBranchCompareImmediate(inst);  // operand 1 immediate (native dispatch)
                if (discVal == null) {                           // operand 1 register -> Anchor lddw'd const
                    String src = registerOperand(inst, 1);
                    if (src != null) discVal = lddwVals.get(src);
                }
                if (reg != null && discVal != null) {
                    // Map the case value to the block that runs when the discriminator MATCHES.
                    // For `jeq R,V,T` that is the branch target T; for `jne R,V,T` the equal case
                    // is the fall-through (T is the not-equal/skip path). Getting this backwards
                    // mislabels skip/error blocks as handlers and misses the real ones.
                    Instruction nextInst = inst.getNext();
                    Address handlerAddr = null;
                    if (mnem.startsWith("jeq")) {
                        for (Address ft : inst.getFlows()) {
                            if (nextInst == null || !ft.equals(nextInst.getAddress())) { handlerAddr = ft; break; }
                        }
                    } else if (nextInst != null) {
                        handlerAddr = nextInst.getAddress();
                    }
                    if (handlerAddr != null) {
                        byReg.computeIfAbsent(reg, k -> new HashMap<>()).put(discVal, handlerAddr);
                        firstSeen.putIfAbsent(reg, inst.getAddress());
                    }
                }
            }
        }

        // Pick the discriminator register: the one matched against the most distinct case
        // values. Require at least two — a lone comparison is far more likely a zero/null
        // guard than a dispatch, and mislabeling it is worse than leaving a (usually
        // inlined) single handler unnamed. Ties break to the earliest comparison so the
        // result is deterministic.
        String dispatchReg = null;
        int bestDistinct = 0;
        Address bestAddr = null;
        for (Map.Entry<String, Map<Long, Address>> e : byReg.entrySet()) {
            int distinct = e.getValue().size();
            if (distinct < 2) continue;
            Address fa = firstSeen.get(e.getKey());
            if (distinct > bestDistinct || (distinct == bestDistinct && fa.compareTo(bestAddr) < 0)) {
                bestDistinct = distinct;
                bestAddr = fa;
                dispatchReg = e.getKey();
            }
        }
        if (dispatchReg == null) return;
        Map<Long, Address> discToTarget = byReg.get(dispatchReg);

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
                            // Native byte discriminators stay decimal (handler_disc_3); the
                            // wide Anchor sha256 discriminators read better as hex.
                            String suffix = Long.compareUnsigned(disc, 0xFFL) <= 0
                                ? Long.toUnsignedString(disc)
                                : "0x" + Long.toUnsignedString(disc, 16);
                            renameAndTypeAs(f, "handler_disc_" + suffix, "process_instruction", log);
                            inst.setComment(CodeUnit.EOL_COMMENT,
                                "Instruction Handler for synthetic dispatch case " + suffix);
                            appendFunctionComment(
                                f,
                                "[DISPATCH ROLE]\n"
                                    + "  Synthetic dispatcher case: " + formatDispatchLabel(disc) + "\n"
                                    + "  Source dispatcher: " + pi.getName() + "\n"
                                    + "  NOTE: This may be an internal control-flow label, not the raw instruction bytes."
                            );
                        }
                    }
                    break;
                }
                if (mnem.equals("exit") || mnem.equals("ret")) break;
                inst = inst.getNext();
            }
        }

    }

    private Long getBranchCompareImmediate(Instruction inst) {
        // Solana SBF conditional branches are rendered as:
        //   JEQ R6, 0x4, 0x00000a28
        // Operand 1 is the compared discriminator/case value. Operand 2 is the
        // branch target and must not be used as a discriminator.
        if (inst.getNumOperands() < 3) return null;
        Object[] compareObjects = inst.getOpObjects(1);
        for (Object obj : compareObjects) {
            if (obj instanceof Scalar) {
                return ((Scalar)obj).getUnsignedValue();
            }
        }
        return null;
    }

    /** The register being compared in a SBF conditional branch (operand 0), or null. */
    private String getBranchCompareRegister(Instruction inst) {
        if (inst.getNumOperands() < 3) return null;
        return registerOperand(inst, 0);
    }

    /** Name of the register in the given operand position, or null if it is not a register. */
    private String registerOperand(Instruction inst, int opIndex) {
        if (opIndex < 0 || opIndex >= inst.getNumOperands()) return null;
        for (Object obj : inst.getOpObjects(opIndex)) {
            if (obj instanceof ghidra.program.model.lang.Register) {
                return ((ghidra.program.model.lang.Register)obj).getName();
            }
        }
        return null;
    }

    /** First scalar (immediate) operand value of an instruction, or null. */
    private Long firstScalar(Instruction inst) {
        for (int i = 0; i < inst.getNumOperands(); i++) {
            Scalar sc = inst.getScalar(i);
            if (sc != null) return sc.getValue();
        }
        return null;
    }

    private void identifyHandlerImplementationCallees(Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        int renamed = 0;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            String handlerName = f.getName();
            if (!handlerName.startsWith("handler_disc_")) continue;
            if (f.getBody().getNumAddresses() > 192) continue;

            int ordinal = 0;
            for (Function called : f.getCalledFunctions(monitor)) {
                monitor.checkCancelled();
                if (called == null || called.isThunk()) continue;
                if (!called.getName().startsWith("FUN_")) continue;
                if (called.getBody().getNumAddresses() < 160) continue;

                String newName = "handler_impl_" + handlerName.substring("handler_disc_".length());
                if (ordinal > 0) {
                    newName = newName + "_" + ordinal;
                }
                ordinal++;

                try {
                    called.setName(newName, SourceType.ANALYSIS);
                    String existing = called.getComment();
                    String note = "[HANDLER ROLE]\n  Business-logic callee reached from " + handlerName + "\n";
                    if (existing == null || !existing.contains("Business-logic callee reached from")) {
                        called.setComment((existing != null ? existing + "\n" : "") + note);
                    }
                    renamed++;
                } catch (Exception e) {
                    Msg.error(this, "Error naming handler implementation at " + called.getEntryPoint(), e);
                }
            }
        }
        if (renamed > 0 && log != null) {
            log.appendMsg("Identified " + renamed + " handler implementation callees");
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

    private String formatDispatchLabel(long disc) {
        return Long.toUnsignedString(disc) + " (0x" + Long.toUnsignedString(disc, 16) + ")";
    }

    private void appendFunctionComment(Function f, String extra) {
        if (extra == null || extra.isEmpty()) return;
        String existing = f.getComment();
        if (existing != null && existing.contains(extra)) return;
        f.setComment((existing == null || existing.isEmpty()) ? extra : existing + "\n" + extra);
    }

    private void renameAndTypeAs(Function f, String newName, String typeName, MessageLog log) {
        try {
            f.setName(newName, SourceType.ANALYSIS);
            SolanaHelperDataTypes helper = SolanaHelperDataTypes.get(f.getProgram(), log);
            if (helper != null) {
                FunctionDefinition funcDef = helper.getSyscallFunctionDef(typeName);
                if (funcDef != null) {
                    if ("process_instruction".equals(typeName)) {
                        // process_instruction (and handlers sharing its ABI) returns the
                        // 16-byte Rust ProgramResult via a hidden sret pointer in R1, which
                        // shifts the real args to R2+. That 6-slot shape overflows the five
                        // input registers, so the default ApplyFunctionSignatureCmd lets the
                        // decompiler re-derive storage and degrade accounts/program_id back to
                        // `long`. Pin the params to the registers explicitly instead.
                        applyShiftedRegisterStorage(f, funcDef);
                    } else {
                        ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                            new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(f.getEntryPoint(), funcDef, SourceType.ANALYSIS);
                        cmd.applyTo(f.getProgram());
                    }
                }
            }
        } catch (Exception e) {
            if (log != null) log.appendMsg("Error naming/typing function " + f.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Apply a sret-shifted Rust prototype by pinning its leading parameters onto the
     * eBPF input registers (R1-R5) with custom storage. The cspec exposes only five
     * input registers, so we map the FunctionDefinition's first five params in order
     * and drop any overflow (e.g. instruction_data_len, which lowers onto the stack
     * and is rarely read in handlers). Custom storage + IMPORTED source commits the
     * prototype so the decompiler preserves the RustAccountInfo and SolPubkey pointer
     * typing instead of re-deriving it from data flow.
     *
     * Caveat: this is also applied to handler_disc_* functions, which are assumed to
     * share the (sret, program_id, accounts, accounts_len, data) ABI. When the dispatch
     * heuristic instead names a thin helper (e.g. a `derive(sret, seeds, seeds_len,
     * program_id)` PDA wrapper), the forced names are wrong — cosmetic only, the values
     * and control flow stay faithful. Tightening this needs leaf-handler vs helper
     * discrimination at the call site.
     */
    private void applyShiftedRegisterStorage(Function f, FunctionDefinition funcDef) throws Exception {
        Program prog = f.getProgram();
        ghidra.program.model.lang.Language lang = prog.getLanguage();
        String[] inRegs = {"R1", "R2", "R3", "R4", "R5"};
        ParameterDefinition[] args = funcDef.getArguments();
        List<Variable> params = new ArrayList<>();
        for (int i = 0; i < args.length && i < inRegs.length; i++) {
            ghidra.program.model.lang.Register reg = lang.getRegister(inRegs[i]);
            if (reg == null) return;  // unexpected processor mismatch — leave the function as-is
            VariableStorage storage = new VariableStorage(prog, reg);
            params.add(new ParameterImpl(args[i].getName(), args[i].getDataType(), storage, prog));
        }
        ReturnParameterImpl ret = new ReturnParameterImpl(funcDef.getReturnType(), prog);
        f.updateFunction(null, ret, params,
            Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.IMPORTED);
    }

    @Override
    public boolean canAnalyze(Program program) {
        return PROCESSOR_NAME.equals(program.getLanguage().getProcessor().toString());
    }
}
