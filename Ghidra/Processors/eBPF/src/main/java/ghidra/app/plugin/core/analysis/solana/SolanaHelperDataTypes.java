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
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

/**
 * Authoritative Solana Data Types for Ghidra.
 *
 * Defines both C ABI (SolAccountInfo, SolInstruction, etc.) and Rust ABI
 * (RustAccountInfo with Rc/RefCell wrappers) types, plus typed function
 * signatures for all 42 Solana syscalls.
 *
 * Reference: agave/platform-tools-sdk/sbf/c/inc/sol/*.h
 * Reference: agave/syscalls/src/lib.rs
 */
public class SolanaHelperDataTypes implements Closeable {

    private static final String SOLANA_DATATYPE_MGR_PROPERTY_KEY = "SolanaDataTypes";

    private DataTypeManager dtm;
    private Map<String, FunctionDefinition> syscallFunctionDefs;

    private SolanaHelperDataTypes(DataTypeManager dtm, Map<String, FunctionDefinition> syscallFunctionDefs) {
        this.dtm = dtm;
        this.syscallFunctionDefs = syscallFunctionDefs;
    }

    @Override
    public void close() throws IOException {
        syscallFunctionDefs = null;
        // Do NOT close dtm — it belongs to the Program and has its own lifecycle
    }

    FunctionDefinition getSyscallFunctionDef(String name) {
        if (syscallFunctionDefs != null) {
            return syscallFunctionDefs.get(name);
        }
        return null;
    }

    static synchronized SolanaHelperDataTypes get(Program program, MessageLog log) {
        return TransientProgramProperties.getProperty(program,
            SOLANA_DATATYPE_MGR_PROPERTY_KEY, SCOPE.ANALYSIS_SESSION, SolanaHelperDataTypes.class,
            () -> buildSolanaDataTypes(program, log));
    }

    private static SolanaHelperDataTypes buildSolanaDataTypes(Program program, MessageLog log) {
        Map<String, FunctionDefinition> syscallFunctionDefs = new HashMap<>();
        DataTypeManager dtm = program.getDataTypeManager();
        int txId = dtm.startTransaction("Build Solana Types");
        boolean success = false;

        try {
            // ================================================================
            // Primitive types
            // ================================================================
            DataType u8 = UnsignedCharDataType.dataType;
            DataType u16 = UnsignedShortDataType.dataType;
            DataType u32 = UnsignedIntegerDataType.dataType;
            DataType u64 = UnsignedLongLongDataType.dataType;
            DataType i32 = IntegerDataType.dataType;
            DataType i64 = LongLongDataType.dataType;
            DataType bool_t = BooleanDataType.dataType;
            DataType f64 = Float8DataType.dataType;
            DataType u8Ptr = new PointerDataType(u8);
            DataType constU8Ptr = new PointerDataType(u8);  // C const not expressible, use u8*
            DataType charPtr = new PointerDataType(CharDataType.dataType);
            DataType voidPtr = PointerDataType.dataType;
            DataType i32Ptr = new PointerDataType(i32);

            // ================================================================
            // Solana Program Error Enum (8 bytes, high bit = error)
            // Reference: agave/platform-tools-sdk/sbf/c/inc/sol/return_data.h
            // ================================================================
            EnumDataType solError = new EnumDataType("SolanaError", 8);
            solError.add("SUCCESS", 0x0L);
            solError.add("Custom", 0x8000000000000000L);
            solError.add("InvalidArgument", 0x8000000000000001L);
            solError.add("InvalidInstructionData", 0x8000000000000002L);
            solError.add("InvalidAccountData", 0x8000000000000003L);
            solError.add("AccountDataTooSmall", 0x8000000000000004L);
            solError.add("InsufficientFunds", 0x8000000000000005L);
            solError.add("IncorrectProgramId", 0x8000000000000006L);
            solError.add("MissingRequiredSignature", 0x8000000000000007L);
            solError.add("AccountAlreadyInitialized", 0x8000000000000008L);
            solError.add("ExecutableAccountExpected", 0x8000000000000009L);
            solError.add("UninitializedAccount", 0x800000000000000aL);
            solError.add("AccountBorrowFailed", 0x800000000000000bL);
            solError.add("AccountBorrowOutstanding", 0x800000000000000cL);
            solError.add("DuplicateAccountOutOfSync", 0x800000000000000dL);
            solError.add("AccountNotRentExempt", 0x800000000000000eL);
            solError.add("InvalidSeeds", 0x800000000000000fL);
            solError.add("InvalidReentrancy", 0x8000000000000010L);
            solError.add("MaxSeedLengthExceeded", 0x8000000000000011L);
            solError.add("InvalidRentSysvar", 0x8000000000000012L);
            solError.add("InvalidClockSysvar", 0x8000000000000013L);
            solError.add("InstructionDataTooSmall", 0x8000000000000014L);
            dtm.addDataType(solError, null);

            // ================================================================
            // SolPubkey (32 bytes) — ED25519 public key
            // Reference: agave/platform-tools-sdk/sbf/c/inc/sol/pubkey.h
            // ================================================================
            StructureDataType solPubkey = new StructureDataType("SolPubkey", 0);
            solPubkey.add(new ArrayDataType(u8, 32, 1), "x", "ED25519 public key bytes");
            DataType solPubkeyDt = dtm.addDataType(solPubkey, null);
            DataType solPubkeyPtr = new PointerDataType(solPubkeyDt);
            DataType constSolPubkeyPtr = new PointerDataType(solPubkeyDt);

            // ================================================================
            // SolBytes — Generic byte slice {addr, len}
            // Reference: agave/platform-tools-sdk/sbf/c/inc/sol/types.h
            // ================================================================
            StructureDataType solBytes = new StructureDataType("SolBytes", 0);
            solBytes.add(constU8Ptr, "addr", "Pointer to bytes");
            solBytes.add(u64, "len", "Number of bytes");
            DataType solBytesDt = dtm.addDataType(solBytes, null);
            DataType solBytesPtr = new PointerDataType(solBytesDt);

            // ================================================================
            // SolSignerSeed — Single PDA seed {addr, len}
            // Reference: agave/platform-tools-sdk/sbf/c/inc/sol/pubkey.h
            // ================================================================
            StructureDataType solSignerSeed = new StructureDataType("SolSignerSeed", 0);
            solSignerSeed.add(constU8Ptr, "addr", "Seed bytes");
            solSignerSeed.add(u64, "len", "Length of seed");
            DataType solSignerSeedDt = dtm.addDataType(solSignerSeed, null);
            DataType solSignerSeedPtr = new PointerDataType(solSignerSeedDt);

            // ================================================================
            // SolSignerSeeds — Array of seeds for PDA signing
            // Reference: agave/platform-tools-sdk/sbf/c/inc/sol/pubkey.h
            // ================================================================
            StructureDataType solSignerSeeds = new StructureDataType("SolSignerSeeds", 0);
            solSignerSeeds.add(new PointerDataType(solSignerSeedDt), "addr", "Array of seeds");
            solSignerSeeds.add(u64, "len", "Number of seeds");
            DataType solSignerSeedsDt = dtm.addDataType(solSignerSeeds, null);
            DataType solSignerSeedsPtr = new PointerDataType(solSignerSeedsDt);

            // ================================================================
            // C ABI: SolAccountInfo (used by C SDK programs)
            // Reference: agave/platform-tools-sdk/sbf/c/inc/sol/entrypoint.h
            // ================================================================
            StructureDataType solAccountInfo = new StructureDataType("SolAccountInfo", 0);
            solAccountInfo.add(solPubkeyPtr, "key", "Public key of the account");
            solAccountInfo.add(new PointerDataType(u64), "lamports", "Pointer to lamports owned");
            solAccountInfo.add(u64, "data_len", "Length of data in bytes");
            solAccountInfo.add(u8Ptr, "data", "On-chain account data");
            solAccountInfo.add(solPubkeyPtr, "owner", "Program that owns this account");
            solAccountInfo.add(u64, "rent_epoch", "Epoch at which account will owe rent");
            solAccountInfo.add(bool_t, "is_signer", "Was the transaction signed by this account's key?");
            solAccountInfo.add(bool_t, "is_writable", "Is the account writable?");
            solAccountInfo.add(bool_t, "executable", "Is the account executable?");
            DataType solAccountInfoDt = dtm.addDataType(solAccountInfo, null);
            DataType solAccountInfoPtr = new PointerDataType(solAccountInfoDt);

            // ================================================================
            // C ABI: SolAccountMeta (for CPI account specification)
            // Reference: agave/platform-tools-sdk/sbf/c/inc/sol/cpi.h
            // ================================================================
            StructureDataType solAccountMeta = new StructureDataType("SolAccountMeta", 0);
            solAccountMeta.add(solPubkeyPtr, "pubkey", "Account public key");
            solAccountMeta.add(bool_t, "is_writable", "Is the account writable?");
            solAccountMeta.add(bool_t, "is_signer", "Is the account a signer?");
            DataType solAccountMetaDt = dtm.addDataType(solAccountMeta, null);

            // ================================================================
            // C ABI: SolInstruction (for CPI)
            // Reference: agave/platform-tools-sdk/sbf/c/inc/sol/cpi.h
            // ================================================================
            StructureDataType solInstruction = new StructureDataType("SolInstruction", 0);
            solInstruction.add(solPubkeyPtr, "program_id", "Program to invoke");
            solInstruction.add(new PointerDataType(solAccountMetaDt), "accounts", "Account metadata array");
            solInstruction.add(u64, "account_len", "Number of accounts");
            solInstruction.add(u8Ptr, "data", "Instruction data");
            solInstruction.add(u64, "data_len", "Length of instruction data");
            DataType solInstructionDt = dtm.addDataType(solInstruction, null);
            DataType solInstructionPtr = new PointerDataType(solInstructionDt);

            // ================================================================
            // C ABI: SolParameters (deserialized entrypoint input)
            // Reference: agave/platform-tools-sdk/sbf/c/inc/sol/entrypoint.h
            // ================================================================
            StructureDataType solParameters = new StructureDataType("SolParameters", 0);
            solParameters.add(solAccountInfoPtr, "ka", "Array of SolAccountInfo");
            solParameters.add(u64, "ka_num", "Number of accounts");
            solParameters.add(constU8Ptr, "data", "Instruction data");
            solParameters.add(u64, "data_len", "Length of instruction data");
            solParameters.add(constSolPubkeyPtr, "program_id", "Current program's public key");
            dtm.addDataType(solParameters, null);

            // ================================================================
            // Rust ABI: RustRcRefCell types (for Rust SDK programs)
            // ================================================================
            StructureDataType rustRcLamports = new StructureDataType("RustRcRefCellLamports", 32);
            rustRcLamports.replaceAtOffset(0, u64, 8, "strong", "Reference count");
            rustRcLamports.replaceAtOffset(8, u64, 8, "weak", "Weak reference count");
            rustRcLamports.replaceAtOffset(16, i64, 8, "borrow_state", "RefCell borrow state");
            rustRcLamports.replaceAtOffset(24, new PointerDataType(u64), 8, "value", "Lamports value pointer");
            DataType rustRcLamportsDt = dtm.addDataType(rustRcLamports, null);

            StructureDataType rustRcData = new StructureDataType("RustRcRefCellData", 48);
            rustRcData.replaceAtOffset(0, u64, 8, "strong", "Reference count");
            rustRcData.replaceAtOffset(8, u64, 8, "weak", "Weak reference count");
            rustRcData.replaceAtOffset(16, i64, 8, "borrow_state", "RefCell borrow state");
            rustRcData.replaceAtOffset(24, u8Ptr, 8, "value", "Data buffer pointer");
            rustRcData.replaceAtOffset(32, u64, 8, "length", "Data length");
            rustRcData.replaceAtOffset(40, u64, 8, "capacity", "Buffer capacity");
            DataType rustRcDataDt = dtm.addDataType(rustRcData, null);

            // ================================================================
            // Rust ABI: RustAccountInfo (48 bytes, with Rc<RefCell<>> wrappers)
            // ================================================================
            StructureDataType rustAccountInfo = new StructureDataType("RustAccountInfo", 48);
            rustAccountInfo.replaceAtOffset(0, solPubkeyPtr, 8, "key", "Account public key");
            rustAccountInfo.replaceAtOffset(8, new PointerDataType(rustRcLamportsDt), 8, "lamports", "Rc<RefCell<&mut u64>>");
            rustAccountInfo.replaceAtOffset(16, new PointerDataType(rustRcDataDt), 8, "data", "Rc<RefCell<&mut [u8]>>");
            rustAccountInfo.replaceAtOffset(24, solPubkeyPtr, 8, "owner", "Program owner");
            rustAccountInfo.replaceAtOffset(32, u64, 8, "rent_epoch", "Epoch for rent collection");
            rustAccountInfo.replaceAtOffset(40, bool_t, 1, "is_signer", "Signed by this key?");
            rustAccountInfo.replaceAtOffset(41, bool_t, 1, "is_writable", "Account writable?");
            rustAccountInfo.replaceAtOffset(42, bool_t, 1, "executable", "Account executable?");
            DataType rustAccountInfoDt = dtm.addDataType(rustAccountInfo, null);
            DataType rustAccountInfoPtr = new PointerDataType(rustAccountInfoDt);

            // ================================================================
            // RustDeserializeResult (entrypoint deserialization output)
            // ================================================================
            StructureDataType rustDeserializeResult = new StructureDataType("RustDeserializeResult", 56);
            rustDeserializeResult.replaceAtOffset(0, u64, 8, "result_discriminant", "0=Ok, nonzero=Err (Rust Result<> tag)");
            rustDeserializeResult.replaceAtOffset(8, rustAccountInfoPtr, 8, "accounts", "Array of accounts");
            rustDeserializeResult.replaceAtOffset(16, u64, 8, "accounts_len", null);
            rustDeserializeResult.replaceAtOffset(24, u64, 8, "accounts_cap", null);
            rustDeserializeResult.replaceAtOffset(32, u8Ptr, 8, "data", "Instruction data");
            rustDeserializeResult.replaceAtOffset(40, u64, 8, "data_len", null);
            rustDeserializeResult.replaceAtOffset(48, solPubkeyPtr, 8, "program_id", null);
            DataType rustDeserializeResultDt = dtm.addDataType(rustDeserializeResult, null);
            DataType rustDeserializeResultPtr = new PointerDataType(rustDeserializeResultDt);

            // ================================================================
            // Sysvar structures
            // ================================================================
            StructureDataType solClock = new StructureDataType("SolClock", 40);
            solClock.replaceAtOffset(0, u64, 8, "slot", "Current slot");
            solClock.replaceAtOffset(8, i64, 8, "epoch_start_timestamp", null);
            solClock.replaceAtOffset(16, u64, 8, "epoch", "Current epoch");
            solClock.replaceAtOffset(24, u64, 8, "leader_schedule_epoch", null);
            solClock.replaceAtOffset(32, i64, 8, "unix_timestamp", "Current timestamp");
            DataType solClockDt = dtm.addDataType(solClock, null);
            DataType solClockPtr = new PointerDataType(solClockDt);

            StructureDataType solRent = new StructureDataType("SolRent", 17);
            solRent.replaceAtOffset(0, u64, 8, "lamports_per_byte_year", null);
            solRent.replaceAtOffset(8, f64, 8, "exemption_threshold", null);
            solRent.replaceAtOffset(16, u8, 1, "burn_percent", null);
            DataType solRentDt = dtm.addDataType(solRent, null);
            DataType solRentPtr = new PointerDataType(solRentDt);

            StructureDataType solEpochSchedule = new StructureDataType("SolEpochSchedule", 0);
            solEpochSchedule.add(u64, "slots_per_epoch", null);
            solEpochSchedule.add(u64, "leader_schedule_slot_offset", null);
            solEpochSchedule.add(bool_t, "warmup", null);
            solEpochSchedule.add(u64, "first_normal_epoch", null);
            solEpochSchedule.add(u64, "first_normal_slot", null);
            DataType solEpochScheduleDt = dtm.addDataType(solEpochSchedule, null);
            DataType solEpochSchedulePtr = new PointerDataType(solEpochScheduleDt);

            // ================================================================
            // Serialized Account Layout (binary format in input buffer)
            // Reference: agave/platform-tools-sdk/sbf/c/inc/sol/deserialize.h
            // ================================================================
            StructureDataType solSerializedAccount = new StructureDataType("SolSerializedAccount", 0);
            solSerializedAccount.add(u8, "dup_marker", "0xFF=unique, else=duplicate index");
            solSerializedAccount.add(bool_t, "is_signer", "SECURITY: Was tx signed by this key?");
            solSerializedAccount.add(bool_t, "is_writable", "SECURITY: Can account be modified?");
            solSerializedAccount.add(bool_t, "executable", "Is account executable?");
            solSerializedAccount.add(new ArrayDataType(u8, 4, 1), "padding", "Alignment padding");
            solSerializedAccount.add(new ArrayDataType(u8, 32, 1), "key", "Account public key (32 bytes)");
            solSerializedAccount.add(new ArrayDataType(u8, 32, 1), "owner", "SECURITY: Owner program (32 bytes)");
            solSerializedAccount.add(u64, "lamports", "SECURITY: Lamports in account");
            solSerializedAccount.add(u64, "data_len", "Length of account data");
            // data bytes follow (variable length), then MAX_PERMITTED_DATA_INCREASE padding, then rent_epoch
            dtm.addDataType(solSerializedAccount, null);

            // ================================================================
            // SYSCALL SIGNATURES — All 42 Solana syscalls
            // Reference: agave/platform-tools-sdk/sbf/c/inc/sol/*.h
            // ================================================================

            // --- Core runtime ---
            addFunc(syscallFunctionDefs, dtm, "abort", VoidDataType.dataType);
            addFunc(syscallFunctionDefs, dtm, "sol_panic_", VoidDataType.dataType,
                p("file", charPtr), p("len", u64), p("line", u64), p("column", u64));

            // --- Logging ---
            addFunc(syscallFunctionDefs, dtm, "sol_log_", VoidDataType.dataType,
                p("message", charPtr), p("len", u64));
            addFunc(syscallFunctionDefs, dtm, "sol_log_64_", VoidDataType.dataType,
                p("arg1", u64), p("arg2", u64), p("arg3", u64), p("arg4", u64), p("arg5", u64));
            addFunc(syscallFunctionDefs, dtm, "sol_log_pubkey", VoidDataType.dataType,
                p("pubkey", constSolPubkeyPtr));
            addFunc(syscallFunctionDefs, dtm, "sol_log_compute_units_", VoidDataType.dataType);
            addFunc(syscallFunctionDefs, dtm, "sol_log_data", VoidDataType.dataType,
                p("fields", solBytesPtr), p("fields_len", u64));

            // --- CPI (Cross-Program Invocation) ---
            // This is the C ABI version — programs compiled with the C SDK use this
            addFunc(syscallFunctionDefs, dtm, "sol_invoke_signed_c", u64,
                p("instruction", new PointerDataType(solInstructionDt)),
                p("account_infos", solAccountInfoPtr),
                p("account_infos_len", i32),
                p("signers_seeds", new PointerDataType(solSignerSeedsDt)),
                p("signers_seeds_len", i32));
            // Rust ABI version — programs compiled with the Rust SDK use this
            addFunc(syscallFunctionDefs, dtm, "sol_invoke_signed_rust", u64,
                p("instruction", u8Ptr),
                p("account_infos", u8Ptr),
                p("account_infos_len", u64),
                p("signers_seeds", u8Ptr),
                p("signers_seeds_len", u64));

            // --- Memory operations ---
            addFunc(syscallFunctionDefs, dtm, "sol_memcpy_", u64,
                p("dst", u8Ptr), p("src", constU8Ptr), p("n", u64));
            addFunc(syscallFunctionDefs, dtm, "sol_memmove_", u64,
                p("dst", u8Ptr), p("src", constU8Ptr), p("n", u64));
            addFunc(syscallFunctionDefs, dtm, "sol_memset_", u64,
                p("dst", u8Ptr), p("val", u64), p("n", u64));
            addFunc(syscallFunctionDefs, dtm, "sol_memcmp_", u64,
                p("s1", constU8Ptr), p("s2", constU8Ptr), p("n", u64), p("result", i32Ptr));

            // --- Cryptographic hashing ---
            addFunc(syscallFunctionDefs, dtm, "sol_sha256", u64,
                p("bytes", solBytesPtr), p("bytes_len", i32), p("result", u8Ptr));
            addFunc(syscallFunctionDefs, dtm, "sol_keccak256", u64,
                p("bytes", solBytesPtr), p("bytes_len", i32), p("result", u8Ptr));
            addFunc(syscallFunctionDefs, dtm, "sol_blake3", u64,
                p("bytes", solBytesPtr), p("bytes_len", i32), p("result", u8Ptr));
            addFunc(syscallFunctionDefs, dtm, "sol_secp256k1_recover", u64,
                p("hash", constU8Ptr), p("recovery_id", u64),
                p("signature", constU8Ptr), p("result", u8Ptr));
            addFunc(syscallFunctionDefs, dtm, "sol_poseidon", u64,
                p("parameters", u64), p("endianness", u64),
                p("vals", u8Ptr), p("vals_len", u64), p("result", u8Ptr));

            // --- PDA (Program Derived Address) ---
            addFunc(syscallFunctionDefs, dtm, "sol_create_program_address", u64,
                p("seeds", solSignerSeedPtr), p("seeds_len", i32),
                p("program_id", constSolPubkeyPtr), p("result", solPubkeyPtr));
            addFunc(syscallFunctionDefs, dtm, "sol_try_find_program_address", u64,
                p("seeds", solSignerSeedPtr), p("seeds_len", i32),
                p("program_id", constSolPubkeyPtr), p("result", solPubkeyPtr),
                p("bump_seed", u8Ptr));

            // --- Sysvar access ---
            addFunc(syscallFunctionDefs, dtm, "sol_get_clock_sysvar", u64,
                p("sysvar", solClockPtr));
            addFunc(syscallFunctionDefs, dtm, "sol_get_rent_sysvar", u64,
                p("sysvar", solRentPtr));
            addFunc(syscallFunctionDefs, dtm, "sol_get_epoch_schedule_sysvar", u64,
                p("sysvar", solEpochSchedulePtr));
            addFunc(syscallFunctionDefs, dtm, "sol_get_fees_sysvar", u64,
                p("sysvar", u8Ptr));
            addFunc(syscallFunctionDefs, dtm, "sol_get_epoch_rewards_sysvar", u64,
                p("sysvar", u8Ptr));
            addFunc(syscallFunctionDefs, dtm, "sol_get_last_restart_slot", u64,
                p("sysvar", u8Ptr));
            addFunc(syscallFunctionDefs, dtm, "sol_get_sysvar", u64,
                p("sysvar_id", constU8Ptr), p("var_addr", u8Ptr),
                p("offset", u64), p("length", u64));

            // --- Program state ---
            addFunc(syscallFunctionDefs, dtm, "sol_get_stack_height", u64);
            addFunc(syscallFunctionDefs, dtm, "sol_set_return_data", VoidDataType.dataType,
                p("data", constU8Ptr), p("len", u64));
            addFunc(syscallFunctionDefs, dtm, "sol_get_return_data", u64,
                p("buffer", u8Ptr), p("max_len", u64), p("program_id", solPubkeyPtr));
            addFunc(syscallFunctionDefs, dtm, "sol_get_processed_sibling_instruction", u64,
                p("index", u64), p("meta", u8Ptr), p("program_id", u8Ptr),
                p("data", u8Ptr), p("accounts", u8Ptr));
            addFunc(syscallFunctionDefs, dtm, "sol_remaining_compute_units", u64);

            // --- Curve25519 / BLS12-381 operations ---
            addFunc(syscallFunctionDefs, dtm, "sol_curve_validate_point", u64,
                p("curve_id", u64), p("point", constU8Ptr));
            addFunc(syscallFunctionDefs, dtm, "sol_curve_group_op", u64,
                p("curve_id", u64), p("op", u64),
                p("left_input", constU8Ptr), p("right_input", constU8Ptr), p("result", u8Ptr));
            addFunc(syscallFunctionDefs, dtm, "sol_curve_multiscalar_mul", u64,
                p("curve_id", u64), p("scalars", constU8Ptr),
                p("points", constU8Ptr), p("result", u8Ptr));
            addFunc(syscallFunctionDefs, dtm, "sol_curve_decompress", u64,
                p("curve_id", u64), p("point", constU8Ptr), p("result", u8Ptr));
            addFunc(syscallFunctionDefs, dtm, "sol_curve_pairing_map", u64,
                p("curve_id", u64), p("input_a", constU8Ptr),
                p("input_b", constU8Ptr), p("result", u8Ptr));

            // --- Alt_bn128 ---
            addFunc(syscallFunctionDefs, dtm, "sol_alt_bn128_group_op", u64,
                p("op", u64), p("input", constU8Ptr), p("input_size", u64), p("result", u8Ptr));
            addFunc(syscallFunctionDefs, dtm, "sol_alt_bn128_compression", u64,
                p("op", u64), p("input", constU8Ptr), p("input_size", u64), p("result", u8Ptr));

            // --- Big modular exponentiation ---
            addFunc(syscallFunctionDefs, dtm, "sol_big_mod_exp", u64,
                p("params", constU8Ptr), p("result", u8Ptr));

            // --- Epoch stake ---
            addFunc(syscallFunctionDefs, dtm, "sol_get_epoch_stake", u64,
                p("pubkey", constU8Ptr));

            // --- Memory allocator (deprecated) ---
            addFunc(syscallFunctionDefs, dtm, "sol_alloc_free_", u64,
                p("size", u64), p("free_addr", u64));

            // ================================================================
            // Internal function signatures (not syscalls, but commonly identified)
            // ================================================================
            addFunc(syscallFunctionDefs, dtm, "sol_deserialize", solError,
                p("result", rustDeserializeResultPtr), p("input", u8Ptr));
            addFunc(syscallFunctionDefs, dtm, "sol_lib_invoke", solError,
                p("ctx", voidPtr), p("instruction", u8Ptr),
                p("accounts", new PointerDataType(rustAccountInfoPtr)), p("accounts_len", u64));
            addFunc(syscallFunctionDefs, dtm, "sol_lib_invoke_signed", solError,
                p("ctx", voidPtr), p("instruction", u8Ptr),
                p("accounts", new PointerDataType(rustAccountInfoPtr)), p("accounts_len", u64),
                p("seeds", u8Ptr));
            addFunc(syscallFunctionDefs, dtm, "sol_lib_get_clock", solError,
                p("sysvar", solClockPtr));
            addFunc(syscallFunctionDefs, dtm, "sol_lib_get_rent", solError,
                p("sysvar", solRentPtr));
            addFunc(syscallFunctionDefs, dtm, "process_instruction", solError,
                p("program_id", solPubkeyPtr), p("accounts", rustAccountInfoPtr),
                p("accounts_len", u64), p("instruction_data", u8Ptr), p("instruction_data_len", u64));
            addFunc(syscallFunctionDefs, dtm, "entrypoint", solError,
                p("input", u8Ptr));

            success = true;
        } finally {
            dtm.endTransaction(txId, success);
        }

        return new SolanaHelperDataTypes(dtm, syscallFunctionDefs);
    }

    /** Helper to create a named ParameterDefinition */
    private static ParameterDefinition p(String name, DataType type) {
        return new ParameterDefinitionImpl(name, type, null);
    }

    /** Register a function definition with named parameters */
    private static void addFunc(Map<String, FunctionDefinition> map, DataTypeManager dtm,
            String name, DataType returnType, ParameterDefinition... params) {
        FunctionDefinitionDataType fdt = new FunctionDefinitionDataType(name);
        fdt.setReturnType(returnType);
        fdt.setArguments(params);
        map.put(name, (FunctionDefinition) dtm.addDataType(fdt, null));
    }
}
