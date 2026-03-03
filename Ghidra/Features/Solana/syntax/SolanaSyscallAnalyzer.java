/**
 * Solana Syscall Analyzer for Ghidra
 * Identifies and labels Solana runtime syscalls in eBPF code
 */

package solana.syntax;

import generic.toolprogramanalyze.*;
import ghidra.app.analyzer.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.util.*;
import java.util.*;

public class SolanaSyscallAnalyzer extends AbstractAnalyzer {
    
    private static final AnalyzerProperties properties = new AnalyzerProperties();
    
    private static final Set<String> SOLANA_SYSCALLS = new HashSet<>(Arrays.asList(
        "sol_log", "sol_log_data", "sol_invoke", "sol_invoke_signed",
        "sol_invoke_signed_all", "sol_allocate", "sol_assign", "sol_return",
        "sol_create_account", "sol_create_account_with_seed", "sol_close_account",
        "sol_memmove", "sol_keccak256", "sol_sha256", "sol_ripemd160",
        "sol_secp256k1_recover", "sol_secp256r1_verify", "sol_ed25519_verify",
        "sol_ed25519_prehash_verify", "sol_sha3_256", "sol_blake3"
    ));
    
    public SolanaSyscallAnalyzer() {
        super("Solana Syscall Labeler", "Identifies Solana runtime syscalls", AnalyzerType.BYTECODE);
        setCategory(Category.ANALYSIS);
        setPriority(AnalyzerPriority.HIGH, this);
        setDuration(5000);
    }
    
    @Override
    public boolean canAnalyze(Program program) {
        Language language = program.getLanguage();
        return language != null && language.getName().contains("eBPF");
    }
    
    @Override
    public boolean initialize(Program program, Monitor monitor) {
        return true;
    }
    
    @Override
    public void analyze(Program program, Set<Domain> domains, Monitor monitor) 
            throws InterruptedException {
        
        SymbolTable symbolTable = program.getSymbolTable();
        
        // Label existing syscall symbols
        for (Symbol symbol : symbolTable.getSymbols()) {
            if (SOLANA_SYSCALLS.contains(symbol.getName())) {
                symbol.setSourceType(SourceType.ANALYST);
            }
        }
        
        // Scan for syscall instructions
        Listing listing = program.getListing();
        for (Instruction instruction : listing.getInstructions(null, true)) {
            String mnemonic = instruction.getMnemonicString();
            if (mnemonic.equals("syscall") || mnemonic.equals("ebpf_syscall")) {
                String syscallName = identifySyscall(instruction);
                if (syscallName != null) {
                    Address addr = instruction.getAddress();
                    Symbol symbol = new Symbol(symbolTable, syscallName, 
                                              addr, SymbolType.LABEL, SourceType.ANALYST);
                    symbolTable.addSymbol(symbol);
                }
            }
            monitor.checkInterrupted();
        }
    }
    
    private String identifySyscall(Instruction instruction) {
        Operand op = instruction.getOperand(0);
        if (op == null || !op.isImmediate()) {
            return null;
        }
        int syscallNum = op.getImmediate().getInt();
        return getSyscallName(syscallNum);
    }
    
    private String getSyscallName(int num) {
        String[] names = {
            "sol_log", "sol_log_data", "sol_invoke", "sol_invoke_signed",
            "sol_invoke_signed_all", "sol_allocate", "sol_assign", "sol_return",
            "sol_create_account", "sol_create_account_with_seed", "sol_close_account",
            "sol_memmove", "sol_keccak256", "sol_sha256", "sol_ripemd160",
            "sol_secp256k1_recover", "sol_secp256r1_verify", "sol_ed25519_verify",
            "sol_ed25519_prehash_verify", "sol_sha3_256", "sol_blake3"
        };
        return (num >= 0 && num < names.length) ? names[num] : null;
    }
    
    @Override
    public Collection<Category> getCategories() {
        return Collections.singleton(Category.ANALYSIS);
    }
    
    @Override
    public AnalyzerProperties getProperties() {
        return properties;
    }
}
