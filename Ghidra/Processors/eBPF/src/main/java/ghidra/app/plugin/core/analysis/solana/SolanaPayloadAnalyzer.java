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

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Advanced payload recovery for Solana.
 * Synthesizes structures for Borsh instruction data and Account state.
 * Performs usage-based semantic naming of fields.
 */
public class SolanaPayloadAnalyzer {

    private static final int ACCOUNT_STRIDE = 0x50;
    private static final int[] ACCOUNT_FIELD_OFFSETS = {0x00, 0x01, 0x02, 0x03, 0x08, 0x28, 0x48, 0x50};

    public static void analyze(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException {
        DataTypeManager dtm = program.getDataTypeManager();
        int borshCount = 0;
        int stateCount = 0;

        for (Function f : program.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            
            // Borsh Instruction Data Recovery — named handlers and their implementation callees
            String fname = f.getName();
            boolean isBorshCandidate = fname.startsWith("handler_disc_")
                || fname.startsWith("handler_impl_")
                || fname.equals("process_instruction")
                || (fname.startsWith("FUN_")
                    && f.getBody().getNumAddresses() > 200
                    && isLikelyHandlerCallee(f, monitor));
            if (isBorshCandidate) {
                Structure borshStruct = recoverBorshStruct(f, dtm);
                if (borshStruct != null) {
                    applyBorshToFunction(f, borshStruct, log);
                    borshCount++;
                }
            }

            // Account State Recovery
            Structure stateStruct = recoverAccountStateStruct(f, dtm);
            if (stateStruct != null) {
                stateCount++;
            }
        }

        if (log != null && (borshCount > 0 || stateCount > 0)) {
            log.appendMsg("Solana Decompiler: Synthesized " + borshCount + " Borsh payloads and " + stateCount + " Account States");
        }
    }

    private static Structure recoverBorshStruct(Function f, DataTypeManager dtm) {
        Program program = f.getProgram();
        TreeMap<Integer, Integer> offsets = new TreeMap<>();
        Map<Integer, String> semanticNames = new HashMap<>();
        int instructionLikeReads = 0;
        int accountMetadataReads = 0;
        boolean hasAnchorDisc = false;
        
        InstructionIterator iter = program.getListing().getInstructions(f.getBody(), true);
        while (iter.hasNext()) {
            Instruction inst = iter.next();
            String mnem = inst.getMnemonicString().toLowerCase();
            
            if (mnem.startsWith("ldx") && inst.getNumOperands() >= 3) {
                // LDX: op[0]=dst_reg, op[1]=base_reg, op[2]=offset_scalar
                Object[] ops = inst.getOpObjects(2);
                if (ops.length >= 1 && ops[0] instanceof ghidra.program.model.scalar.Scalar) {
                    int offset = (int)((ghidra.program.model.scalar.Scalar)ops[0]).getSignedValue();
                    if (offset >= 0 && offset < 2048) {
                        if (looksLikeAccountMetadataOffset(offset)) {
                            accountMetadataReads++;
                            continue;
                        }

                        int size = getWidth(mnem);
                        offsets.put(offset, size);
                        instructionLikeReads++;
                        if (offset == 0 && size == 8) {
                            hasAnchorDisc = true;
                        }
                        
                        // Semantic usage tracking
                        String usage = inferUsage(inst);
                        if (usage != null) semanticNames.put(offset, usage);
                    }
                }
            }
        }

        if (offsets.size() < 2) return null;
        if (instructionLikeReads == 0) return null;
        if (accountMetadataReads > instructionLikeReads * 2) return null;

        String name = "BorshPayload_" + f.getName();
        int totalSize = offsets.lastKey() + offsets.get(offsets.lastKey());
        StructureDataType struct = new StructureDataType(name, totalSize);

        if (hasAnchorDisc) {
            try {
                struct.replaceAtOffset(0, UnsignedLongLongDataType.dataType, 8,
                    "anchor_discriminator", "8-byte Anchor instruction discriminator");
            } catch (Exception e) {}
        }
        
        for (Map.Entry<Integer, Integer> entry : offsets.entrySet()) {
            int off = entry.getKey();
            if (off == 0 && hasAnchorDisc) continue;
            int sz = entry.getValue();
            String fieldName = semanticNames.getOrDefault(off, "field_" + off);
            try {
                struct.replaceAtOffset(off, getDt(sz), sz, fieldName, "Auto-recovered Borsh field");
            } catch (Exception e) {}
        }

        DataType added = dtm.addDataType(struct, null);
        return (added instanceof Structure) ? (Structure) added : null;
    }

    private static boolean looksLikeAccountMetadataOffset(int offset) {
        if (offset < 0) return false;
        int remainder = offset % ACCOUNT_STRIDE;
        for (int candidate : ACCOUNT_FIELD_OFFSETS) {
            if (remainder == candidate) return true;
        }
        return false;
    }

    private static boolean isLikelyHandlerCallee(Function f, TaskMonitor monitor) throws CancelledException {
        for (Function caller : f.getCallingFunctions(monitor)) {
            String callerName = caller.getName();
            if (callerName.startsWith("handler_disc_") || callerName.equals("process_instruction")) {
                return true;
            }
        }
        return false;
    }

    private static String inferUsage(Instruction inst) {
        // Look ahead for calls that use the register loaded from this offset
        Object[] ops = inst.getOpObjects(0);
        if (ops == null || ops.length == 0) return null;
        Instruction next = inst.getNext();
        for (int i = 0; i < 5 && next != null; i++) {
            String mnem = next.getMnemonicString().toLowerCase();
            if (mnem.startsWith("call")) {
                Reference[] refs = next.getReferencesFrom();
                if (refs.length > 0) {
                    String target = refs[0].getToAddress().toString();
                    ghidra.program.model.scalar.Scalar sc = inst.getScalar(2);
                    if (sc == null) return null;
                    long val = sc.getUnsignedValue();
                    if (target.contains("sol_log_pubkey")) return "pubkey_" + val;
                    if (target.contains("sol_memcpy")) return "len_" + val;
                }
            }
            next = next.getNext();
        }
        return null;
    }

    private static Structure recoverAccountStateStruct(Function f, DataTypeManager dtm) {
        Program program = f.getProgram();
        TreeMap<Integer, Integer> offsets = new TreeMap<>();
        boolean hasAnchorDisc = false;
        
        InstructionIterator iter = program.getListing().getInstructions(f.getBody(), true);
        while (iter.hasNext()) {
            Instruction inst = iter.next();
            String mnem = inst.getMnemonicString().toLowerCase();
            if (mnem.startsWith("stx") || mnem.startsWith("st")) {
                // STX: op[0]=base_reg, op[1]=offset_scalar, op[2]=src_reg (3 operands)
                // ST:  op[0]=base_reg, op[1]=offset_scalar, op[2]=imm_value (3 operands)
                if (inst.getNumOperands() < 3) continue;
                Object[] stOps = inst.getOpObjects(1);
                if (stOps.length >= 1 && stOps[0] instanceof ghidra.program.model.scalar.Scalar) {
                    int offset = (int)((ghidra.program.model.scalar.Scalar)stOps[0]).getSignedValue();
                    if (offset >= 0 && offset < 10000) {
                        int size = getWidth(mnem);
                        offsets.put(offset, size);
                        if (offset == 0 && size == 8) hasAnchorDisc = true;
                    }
                }
            }
        }

        if (offsets.size() < 3) return null;

        String name = "AccountState_" + f.getName();
        int totalSize = offsets.lastKey() + offsets.get(offsets.lastKey());
        StructureDataType struct = new StructureDataType(name, totalSize);
        
        if (hasAnchorDisc) {
            try { struct.replaceAtOffset(0, UnsignedLongLongDataType.dataType, 8, "anchor_discriminator", "8-byte SHA256"); } catch (Exception e) {}
        }

        for (Map.Entry<Integer, Integer> entry : offsets.entrySet()) {
            int off = entry.getKey();
            if (off == 0 && hasAnchorDisc) continue;
            int sz = entry.getValue();
            try {
                struct.replaceAtOffset(off, getDt(sz), sz, "state_field_" + off, "Auto-recovered state");
            } catch (Exception e) {}
        }

        DataType added = dtm.addDataType(struct, null);
        return (added instanceof Structure) ? (Structure) added : null;
    }

    private static void applyBorshToFunction(Function f, Structure struct, MessageLog log) {
        try {
            Parameter[] params = f.getParameters();
            for (int i = params.length - 1; i >= 0; i--) {
                DataType dt = params[i].getDataType();
                if (dt instanceof PointerDataType) {
                    DataType base = ((PointerDataType)dt).getDataType();
                    if (base.getName().equals("u8") || base.getName().equals("undefined") || base.getName().equals("uchar")) {
                        params[i].setDataType(new PointerDataType(struct), SourceType.ANALYSIS);
                        break;
                    }
                }
            }
            f.updateFunction(null, null, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS, params);
        } catch (Exception e) {}
    }

    static int getWidth(String mnem) {
        if (mnem.endsWith("dw")) return 8;  // LDXDW/STXDW/STDW — must check before "w"
        if (mnem.endsWith("b")) return 1;
        if (mnem.endsWith("h")) return 2;
        if (mnem.endsWith("w")) return 4;
        return 8;
    }

    private static DataType getDt(int size) {
        switch (size) {
            case 1: return UnsignedCharDataType.dataType;
            case 2: return UnsignedShortDataType.dataType;
            case 4: return UnsignedIntegerDataType.dataType;
            case 8: return UnsignedLongLongDataType.dataType;
            default: return new ArrayDataType(UnsignedCharDataType.dataType, size, 1);
        }
    }
}
