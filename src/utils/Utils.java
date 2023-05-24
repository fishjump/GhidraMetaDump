package utils;

import ghidra.program.model.pcode.PcodeOp;

public class Utils {
    static public String PCodeId(PcodeOp pcodeOp) {
        return pcodeOp.getParent().getStart().toString() + ":" + Integer.toString(pcodeOp.getSeqnum().getOrder());
    }

    static public String PCodeId(String addr, int order) {
        return addr + ":" + order;
    }
}
