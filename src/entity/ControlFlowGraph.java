package entity;

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.HashMap;

import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import utils.Utils;

public class ControlFlowGraph {
    public class BasicBlockContext {
        public List<String> preds = new ArrayList<String>();
        public List<String> succs = new ArrayList<String>();

        public BasicBlockContext(PcodeBlockBasic pcodeBlockBasic) {
            for (int i = 0; i < pcodeBlockBasic.getInSize(); i++) {
                var in = pcodeBlockBasic.getIn(i);
                preds.add(in.getStart().toString());
            }

            for (int i = 0; i < pcodeBlockBasic.getOutSize(); i++) {
                var out = pcodeBlockBasic.getOut(i);
                succs.add(out.getStart().toString());
            }
        }

        public List<String> getPreds() {
            return preds;
        }

        public void setPreds(List<String> preds) {
            this.preds = preds;
        }

        public List<String> getSuccs() {
            return succs;
        }

        public void setSuccs(List<String> succs) {
            this.succs = succs;
        }
    }

    public class PCodeContext {
        public List<String> preds = new ArrayList<String>();
        public List<String> succs = new ArrayList<String>();

        public PCodeContext(Function ctx, PcodeOp pcode) {
            // two cases:
            // 1. if a pred and current are in the same BB, just insert and exit
            // 2. if not, visit the last/first of pred/succ bb

            var current = pcode.getParent();
            var inBlockPcodes = ctx.basicblocks.get(current.getStart().toString()).pcodes;

            if (0 <= pcode.getSeqnum().getOrder() - 1) {
                // pred is in the same basic block
                preds.add(Utils.PCodeId(pcode.getParent().getStart().toString(), pcode.getSeqnum().getOrder() - 1));
            } else {
                // find the pred bb and add the last
                for (int i = 0; i < current.getInSize(); i++) {
                    var pred = current.getIn(i);
                    var predBlockPcodes = ctx.basicblocks.get(pred.getStart().toString()).pcodes;
                    if (predBlockPcodes.size() > 0) {
                        var predLast = predBlockPcodes.get(predBlockPcodes.size() - 1);
                        preds.add(predLast);
                    }
                }
            }

            if ((pcode.getSeqnum().getOrder() + 1) < inBlockPcodes.size()) {
                // pred is in the same basic block
                succs.add(Utils.PCodeId(pcode.getParent().getStart().toString(), pcode.getSeqnum().getOrder() + 1));
            } else {
                // find the succ bb and add the first
                for (int i = 0; i < current.getOutSize(); i++) {
                    var succ = current.getOut(i);
                    var succBlockPcodes = ctx.basicblocks.get(succ.getStart().toString()).pcodes;
                    if (succBlockPcodes.size() > 0) {
                        var succLast = succBlockPcodes.get(0);
                        succs.add(succLast);
                    }
                }
            }
        }

        public List<String> getPreds() {
            return preds;
        }

        public void setPreds(List<String> preds) {
            this.preds = preds;
        }

        public List<String> getSuccs() {
            return succs;
        }

        public void setSuccs(List<String> succs) {
            this.succs = succs;
        }
    }

    public Map<String, BasicBlockContext> basicblocks = new HashMap<>();

    public Map<String, PCodeContext> pcodes = new HashMap<>();

    public Map<String, BasicBlockContext> getBasicblocks() {
        return basicblocks;
    }

    public void setBasicblocks(Map<String, BasicBlockContext> basicblocks) {
        this.basicblocks = basicblocks;
    }

    public Map<String, PCodeContext> getPcodes() {
        return pcodes;
    }

    public void setPcodes(Map<String, PCodeContext> pcodes) {
        this.pcodes = pcodes;
    }

    public ControlFlowGraph(Function ctx, HighFunction hF) {
        for (var basicblock : hF.getBasicBlocks()) {
            basicblocks.put(basicblock.getStart().toString(), new BasicBlockContext(basicblock));

            var it = basicblock.getIterator();
            while (it.hasNext()) {
                var pcodeOp = it.next();

                pcodes.put(Utils.PCodeId(pcodeOp), new PCodeContext(ctx, pcodeOp));
            }
        }
    }
}
