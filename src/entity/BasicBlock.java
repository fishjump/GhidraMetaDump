package entity;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.pcode.PcodeBlockBasic;

import utils.Utils;

public class BasicBlock {
    public String id;
    public String entry;
    public String exit;

    public List<String> pcodes = new ArrayList<>();

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
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

    public BasicBlock(PcodeBlockBasic pcodeBB) {
        id = pcodeBB.getStart().toString();
        entry = pcodeBB.getStart().toString();
        exit = pcodeBB.getStop().toString();

        // add pcodes
        var it = pcodeBB.getIterator();
        while (it.hasNext()) {
            var pcodeOp = it.next();
            pcodes.add(Utils.PCodeId(pcodeOp));
        }
    }
}
