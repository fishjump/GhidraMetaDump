package entity;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import ghidra.program.model.pcode.HighFunction;

public class Function {
    public String name;
    public String entry;
    public String exit;

    public Map<String, BasicBlock> basicblocks = new HashMap<>();
    public Map<String, PCode> pcodes = new HashMap<>();
    public Set<String> varnodes = new HashSet<>();
    public Map<String, Symbol> symbols = new HashMap<>();

    public ControlFlowGraph cfg;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEntry() {
        return entry;
    }

    public void setEntry(String entry) {
        this.entry = entry;
    }

    public String getExit() {
        return exit;
    }

    public void setExit(String exit) {
        this.exit = exit;
    }

    public Map<String, BasicBlock> getBasicblocks() {
        return basicblocks;
    }

    public void setBasicblocks(Map<String, BasicBlock> basicblocks) {
        this.basicblocks = basicblocks;
    }

    public Map<String, PCode> getPcodes() {
        return pcodes;
    }

    public void setPcodes(Map<String, PCode> pcodes) {
        this.pcodes = pcodes;
    }

    public Set<String> getVarnodes() {
        return varnodes;
    }

    public void setVarnodes(Set<String> varnodes) {
        this.varnodes = varnodes;
    }

    public Map<String, Symbol> getSymbols() {
        return symbols;
    }

    public void setSymbols(Map<String, Symbol> symbols) {
        this.symbols = symbols;
    }

    public ControlFlowGraph getCfg() {
        return cfg;
    }

    public void setCfg(ControlFlowGraph cfg) {
        this.cfg = cfg;
    }

    public Function(HighFunction hF) {
        var func = hF.getFunction();

        name = func.getName();
        entry = func.getBody().getMinAddress().toString();
        exit = func.getBody().getMaxAddress().toString();

        for (var pcodeBB : hF.getBasicBlocks()) {
            // add basic blocks
            var basicblock = new BasicBlock(pcodeBB);
            basicblocks.put(basicblock.id, basicblock);

            // add pcodes
            var it = pcodeBB.getIterator();
            while (it.hasNext()) {
                var pcodeOp = it.next();
                var pcode = new PCode(pcodeOp);
                pcodes.put(pcode.id, pcode);

                // add varnodes
                for (var input : pcodeOp.getInputs()) {
                    varnodes.add(input.toString());
                }

                if (pcodeOp.getOutput() != null) {
                    varnodes.add(pcodeOp.getOutput().toString());
                }
            }
        }

        hF.getLocalSymbolMap().getSymbols().forEachRemaining((hS) -> {
            var symbol = new Symbol(hS);
            symbols.put(symbol.id, symbol);
        });

        hF.getGlobalSymbolMap().getSymbols().forEachRemaining((hS) -> {
            var symbol = new Symbol(hS);
            symbols.put(symbol.id, symbol);
        });

        cfg = new ControlFlowGraph(this, hF);
    }
}
