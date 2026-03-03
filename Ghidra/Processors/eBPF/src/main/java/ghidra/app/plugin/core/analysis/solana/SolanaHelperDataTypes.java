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

import java.io.Closeable;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.plugin.core.analysis.TransientProgramProperties;
import ghidra.app.plugin.core.analysis.TransientProgramProperties.SCOPE;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Provides Solana-specific data types and syscall function signatures.
 *
 * Structures match the authoritative C definitions from:
 *   agave/platform-tools-sdk/sbf/c/inc/sol/entrypoint.h  (SolAccountInfo)
 *   agave/platform-tools-sdk/sbf/c/inc/sol/cpi.h         (SolInstruction, SolAccountMeta)
 *   agave/platform-tools-sdk/sbf/c/inc/sol/pubkey.h      (SolPubkey, SolSignerSeed, SolSignerSeeds)
 *   agave/platform-tools-sdk/sbf/c/inc/sol/types.h       (SolBytes)
 *
 * Syscall signatures match the actual C API as declared in the header files.
 * Syscalls are looked up by name (not sequential ID) since Solana uses murmur3 hashing.
 */
public class SolanaHelperDataTypes implements Closeable {

    private static final String SOLANA_DATATYPE_MGR_PROPERTY_KEY = "SolanaDataTypes";

    /**
     * Map of syscall name -> C function signature string.
     *
     * These match the actual Solana C SDK declarations from agave/platform-tools-sdk/sbf/c/inc/sol/.
     * All syscalls use the eBPF calling convention (args in r1-r5, return in r0).
     */
    private static final Map<String, String> SOLANA_SYSCALL_SIGNATURES = new HashMap<>();
    static {
        // Core runtime
        SOLANA_SYSCALL_SIGNATURES.put("abort",
            "void abort()");
        SOLANA_SYSCALL_SIGNATURES.put("sol_panic_",
            "void sol_panic_(const char *file, u64 file_len, u64 line, u64 column)");

        // Logging (from sol/log.h)
        SOLANA_SYSCALL_SIGNATURES.put("sol_log_",
            "void sol_log_(const char *message, u64 len)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_log_64_",
            "void sol_log_64_(u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_log_pubkey",
            "void sol_log_pubkey(const SolPubkey *pubkey)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_log_compute_units_",
            "void sol_log_compute_units_()");
        SOLANA_SYSCALL_SIGNATURES.put("sol_log_data",
            "void sol_log_data(SolBytes *fields, u64 fields_len)");

        // CPI - Cross-Program Invocation (from sol/cpi.h)
        SOLANA_SYSCALL_SIGNATURES.put("sol_invoke_signed_c",
            "u64 sol_invoke_signed_c(const SolInstruction *instruction, const SolAccountInfo *account_infos, int account_infos_len, const SolSignerSeeds *signers_seeds, int signers_seeds_len)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_invoke_signed_rust",
            "u64 sol_invoke_signed_rust(const u8 *instruction, u64 instr_len, const u8 *account_infos, u64 account_infos_len, const u8 *signers_seeds)");

        // Memory operations (VM-level: all params are u64 addresses/values)
        SOLANA_SYSCALL_SIGNATURES.put("sol_memcpy_",
            "u64 sol_memcpy_(u8 *dst, const u8 *src, u64 n)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_memmove_",
            "u64 sol_memmove_(u8 *dst, const u8 *src, u64 n)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_memset_",
            "u64 sol_memset_(u8 *dst, u64 c, u64 n)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_memcmp_",
            "u64 sol_memcmp_(const u8 *s1, const u8 *s2, u64 n, int *result)");

        // Cryptographic hashing (from sol/sha.h, sol/keccak.h, sol/secp256k1.h)
        SOLANA_SYSCALL_SIGNATURES.put("sol_sha256",
            "u64 sol_sha256(const SolBytes *bytes, int bytes_len, u8 *result)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_keccak256",
            "u64 sol_keccak256(const SolBytes *bytes, int bytes_len, u8 *result)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_secp256k1_recover",
            "u64 sol_secp256k1_recover(const u8 *hash, u64 recovery_id, const u8 *signature, u8 *result)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_blake3",
            "u64 sol_blake3(const SolBytes *bytes, int bytes_len, u8 *result)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_poseidon",
            "u64 sol_poseidon(u64 parameters, u64 endianness, const u8 *vals, u64 val_len, u8 *result)");

        // PDA - Program Derived Address (from sol/pubkey.h)
        SOLANA_SYSCALL_SIGNATURES.put("sol_create_program_address",
            "u64 sol_create_program_address(const SolSignerSeed *seeds, int seeds_len, const SolPubkey *program_id, SolPubkey *program_address)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_try_find_program_address",
            "u64 sol_try_find_program_address(const SolSignerSeed *seeds, int seeds_len, const SolPubkey *program_id, SolPubkey *program_address, u8 *bump_seed)");

        // Sysvar access
        SOLANA_SYSCALL_SIGNATURES.put("sol_get_clock_sysvar",
            "u64 sol_get_clock_sysvar(u8 *var_addr)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_get_rent_sysvar",
            "u64 sol_get_rent_sysvar(u8 *var_addr)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_get_epoch_schedule_sysvar",
            "u64 sol_get_epoch_schedule_sysvar(u8 *var_addr)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_get_fees_sysvar",
            "u64 sol_get_fees_sysvar(u8 *var_addr)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_get_epoch_rewards_sysvar",
            "u64 sol_get_epoch_rewards_sysvar(u8 *var_addr)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_get_last_restart_slot",
            "u64 sol_get_last_restart_slot(u8 *var_addr)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_get_sysvar",
            "u64 sol_get_sysvar(u8 *var_addr, u8 *id_addr, u64 var_len, u64 offset, u64 length)");

        // Program state (from sol/return_data.h)
        SOLANA_SYSCALL_SIGNATURES.put("sol_get_stack_height",
            "u64 sol_get_stack_height()");
        SOLANA_SYSCALL_SIGNATURES.put("sol_set_return_data",
            "void sol_set_return_data(const u8 *data, u64 data_len)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_get_return_data",
            "u64 sol_get_return_data(u8 *data, u64 data_len, SolPubkey *program_id)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_get_processed_sibling_instruction",
            "u64 sol_get_processed_sibling_instruction(u64 index, u8 *meta, SolPubkey *program_id, u8 *data, u8 *accounts)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_remaining_compute_units",
            "u64 sol_remaining_compute_units()");

        // Curve25519 operations (from sol/curve.h)
        SOLANA_SYSCALL_SIGNATURES.put("sol_curve_validate_point",
            "u64 sol_curve_validate_point(u64 curve_id, const u8 *point, u8 *result)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_curve_group_op",
            "u64 sol_curve_group_op(u64 curve_id, u64 group_op, const u8 *left, const u8 *right, u8 *result)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_curve_multiscalar_mul",
            "u64 sol_curve_multiscalar_mul(u64 curve_id, const u8 *scalars, const u8 *points, u64 num, u8 *result)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_curve_decompress",
            "u64 sol_curve_decompress(u64 curve_id, const u8 *compressed, u8 *result)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_curve_pairing_map",
            "u64 sol_curve_pairing_map(u64 curve_id, const u8 *point, u64 point_len, u8 *result)");

        // Alt_bn128 elliptic curve operations
        SOLANA_SYSCALL_SIGNATURES.put("sol_alt_bn128_group_op",
            "u64 sol_alt_bn128_group_op(u64 group_op, const u8 *input, u64 input_size, u8 *result)");
        SOLANA_SYSCALL_SIGNATURES.put("sol_alt_bn128_compression",
            "u64 sol_alt_bn128_compression(u64 op, const u8 *input, u64 input_size, u8 *result)");

        // Big modular exponentiation
        SOLANA_SYSCALL_SIGNATURES.put("sol_big_mod_exp",
            "u64 sol_big_mod_exp(const u8 *params, u64 params_len, u8 *result, u64 result_len)");

        // Epoch stake query (SIMD-0133)
        SOLANA_SYSCALL_SIGNATURES.put("sol_get_epoch_stake",
            "u64 sol_get_epoch_stake(const u8 *vote_address)");

        // Memory allocator (deprecated but still present in legacy programs)
        SOLANA_SYSCALL_SIGNATURES.put("sol_alloc_free_",
            "u64 sol_alloc_free_(u64 size, u64 free_addr)");
    }

    private DataTypeManager dtm;
    private Map<String, FunctionDefinition> syscallFunctionDefs;

    private SolanaHelperDataTypes(DataTypeManager dtm, Map<String, FunctionDefinition> syscallFunctionDefs) {
        this.dtm = dtm;
        this.syscallFunctionDefs = syscallFunctionDefs;
    }

    @Override
    public void close() throws IOException {
        syscallFunctionDefs = null;
        dtm.close();
    }

    /**
     * Get function definition for a Solana syscall by name.
     * @param name The syscall name (e.g., "sol_log_", "sol_invoke_signed_c")
     * @return The function definition, or null if not found
     */
    FunctionDefinition getSyscallFunctionDef(String name) {
        if (syscallFunctionDefs != null) {
            return syscallFunctionDefs.get(name);
        }
        return null;
    }

    static synchronized SolanaHelperDataTypes get(Program program, MessageLog log) {

        boolean previouslyParsed =
            TransientProgramProperties.hasProperty(program, SOLANA_DATATYPE_MGR_PROPERTY_KEY);
        SolanaHelperDataTypes instance = TransientProgramProperties.getProperty(program,
            SOLANA_DATATYPE_MGR_PROPERTY_KEY, SCOPE.ANALYSIS_SESSION, SolanaHelperDataTypes.class,
            () -> parseSyscallFunctionDefs(program, log));
        if (instance == null && !previouslyParsed) {
            if (log != null) {
                log.appendMsg("Failed to parse Solana syscall function definitions");
            }
        }
        return instance;
    }

    private static SolanaHelperDataTypes parseSyscallFunctionDefs(Program program, MessageLog log) {

        Map<String, FunctionDefinition> syscallFunctionDefs = new HashMap<>();

        boolean success = false;
        DataTypeManager dtm =
            new StandAloneDataTypeManager("Solana", DataOrganizationImpl.getDefaultOrganization());
        int txId = dtm.startTransaction("Parse Solana Types");
        try {
            // Populate basic typedef dependencies for Solana C SDK
            dtm.addDataType(new TypedefDataType("u8", UnsignedCharDataType.dataType), null);
            dtm.addDataType(new TypedefDataType("u16", UnsignedShortDataType.dataType), null);
            dtm.addDataType(new TypedefDataType("u32", UnsignedIntegerDataType.dataType), null);
            dtm.addDataType(new TypedefDataType("u64", UnsignedLongLongDataType.dataType), null);
            dtm.addDataType(new TypedefDataType("i64", LongLongDataType.dataType), null);

            // SolPubkey - 32-byte public key (from sol/pubkey.h)
            StructureDataType solPubkey = new StructureDataType("SolPubkey", 0);
            ArrayDataType pubkeyBytes = new ArrayDataType(UnsignedCharDataType.dataType, 32, 1);
            solPubkey.add(pubkeyBytes, "x", "32-byte public key");
            dtm.addDataType(solPubkey, null);

            // SolBytes - byte array with length (from sol/types.h)
            StructureDataType solBytes = new StructureDataType("SolBytes", 0);
            solBytes.add(PointerDataType.dataType, "addr", "byte data pointer");
            solBytes.add(UnsignedLongLongDataType.dataType, "len", "number of bytes");
            dtm.addDataType(solBytes, null);

            // SolSignerSeed - seed for PDA derivation (from sol/pubkey.h)
            StructureDataType solSignerSeed = new StructureDataType("SolSignerSeed", 0);
            solSignerSeed.add(PointerDataType.dataType, "addr", "Seed bytes");
            solSignerSeed.add(UnsignedLongLongDataType.dataType, "len", "Length of the seed bytes");
            dtm.addDataType(solSignerSeed, null);

            // SolSignerSeeds - array of seeds (from sol/pubkey.h)
            StructureDataType solSignerSeeds = new StructureDataType("SolSignerSeeds", 0);
            solSignerSeeds.add(new PointerDataType(dtm.getDataType("/SolSignerSeed")), "addr", "Array of signer seeds");
            solSignerSeeds.add(UnsignedLongLongDataType.dataType, "len", "Number of seeds");
            dtm.addDataType(solSignerSeeds, null);

            // SolAccountInfo - account info structure (from sol/entrypoint.h)
            // AUTHORITATIVE field order from agave:
            //   SolPubkey *key;
            //   uint64_t *lamports;
            //   uint64_t data_len;
            //   uint8_t *data;
            //   SolPubkey *owner;
            //   uint64_t rent_epoch;
            //   bool is_signer;
            //   bool is_writable;
            //   bool executable;
            StructureDataType solAccountInfo = new StructureDataType("SolAccountInfo", 0);
            solAccountInfo.add(new PointerDataType(dtm.getDataType("/SolPubkey")), "key", "Public key of the account");
            solAccountInfo.add(new PointerDataType(UnsignedLongLongDataType.dataType), "lamports", "Number of lamports owned by this account");
            solAccountInfo.add(UnsignedLongLongDataType.dataType, "data_len", "Length of data in bytes");
            solAccountInfo.add(new PointerDataType(UnsignedCharDataType.dataType), "data", "On-chain data within this account");
            solAccountInfo.add(new PointerDataType(dtm.getDataType("/SolPubkey")), "owner", "Program that owns this account");
            solAccountInfo.add(UnsignedLongLongDataType.dataType, "rent_epoch", "The epoch at which this account will next owe rent");
            solAccountInfo.add(BooleanDataType.dataType, "is_signer", "Transaction was signed by this account's key?");
            solAccountInfo.add(BooleanDataType.dataType, "is_writable", "Is the account writable?");
            solAccountInfo.add(BooleanDataType.dataType, "executable", "This account's data contains a loaded program");
            dtm.addDataType(solAccountInfo, null);

            // SolAccountMeta - CPI account metadata (from sol/cpi.h)
            StructureDataType solAccountMeta = new StructureDataType("SolAccountMeta", 0);
            solAccountMeta.add(new PointerDataType(dtm.getDataType("/SolPubkey")), "pubkey", "An account's public key");
            solAccountMeta.add(BooleanDataType.dataType, "is_writable", "True if the pubkey can be loaded as read-write");
            solAccountMeta.add(BooleanDataType.dataType, "is_signer", "True if requires Transaction signature matching pubkey");
            dtm.addDataType(solAccountMeta, null);

            // SolInstruction - CPI instruction (from sol/cpi.h)
            StructureDataType solInstruction = new StructureDataType("SolInstruction", 0);
            solInstruction.add(new PointerDataType(dtm.getDataType("/SolPubkey")), "program_id", "Pubkey of the instruction processor");
            solInstruction.add(new PointerDataType(dtm.getDataType("/SolAccountMeta")), "accounts", "Metadata for accounts to pass");
            solInstruction.add(UnsignedLongLongDataType.dataType, "account_len", "Number of SolAccountMetas");
            solInstruction.add(new PointerDataType(UnsignedCharDataType.dataType), "data", "Opaque data passed to instruction processor");
            solInstruction.add(UnsignedLongLongDataType.dataType, "data_len", "Length of the data in bytes");
            dtm.addDataType(solInstruction, null);

            // SolParameters - entrypoint parameters (from sol/entrypoint.h)
            StructureDataType solParameters = new StructureDataType("SolParameters", 0);
            solParameters.add(new PointerDataType(dtm.getDataType("/SolAccountInfo")), "ka", "Pointer to array of SolAccountInfo");
            solParameters.add(UnsignedLongLongDataType.dataType, "ka_num", "Number of SolAccountInfo entries");
            solParameters.add(new PointerDataType(UnsignedCharDataType.dataType), "data", "Pointer to instruction data");
            solParameters.add(UnsignedLongLongDataType.dataType, "data_len", "Length of instruction data");
            solParameters.add(new PointerDataType(dtm.getDataType("/SolPubkey")), "program_id", "Program ID of the currently executing program");
            dtm.addDataType(solParameters, null);

            // Parse syscall function signatures
            CParser parser = new CParser(dtm, true, null);
            try {
                for (Map.Entry<String, String> entry : SOLANA_SYSCALL_SIGNATURES.entrySet()) {
                    String name = entry.getKey();
                    String sig = entry.getValue();
                    FunctionDefinition funcDef = (FunctionDefinition) parser.parse(sig + ";");
                    if (funcDef != null) {
                        syscallFunctionDefs.put(name, funcDef);
                    }
                }
            }
            catch (ParseException e) {
                Msg.error(SolanaHelperDataTypes.class, "Solana datatype parse error: " +
                    e.getMessage() + "\n\n" + parser.getParseMessages());
                if (log != null) {
                    log.appendMsg("Parse error: " + e.getMessage());
                }
                return null;
            }

            success = true;
        }
        finally {
            dtm.endTransaction(txId, success);
            if (!success) {
                dtm.close();
            }
        }

        return new SolanaHelperDataTypes(dtm, syscallFunctionDefs);
    }
}
