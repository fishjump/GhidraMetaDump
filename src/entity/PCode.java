package entity;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.pcode.PcodeOp;
import utils.PCodeOpNameCvt;
import utils.Utils;

public class PCode {
    public String id;
    public String operation;
    public String parent;

    // varnode id
    public List<String> inputs = new ArrayList<>();
    public String output;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getOperation() {
        return operation;
    }

    public void setOperation(String operation) {
        this.operation = operation;
    }

    public String getParent() {
        return parent;
    }

    public void setParent(String parent) {
        this.parent = parent;
    }

    public List<String> getInputs() {
        return inputs;
    }

    public void setInputs(List<String> inputs) {
        this.inputs = inputs;
    }

    public String getOutput() {
        return output;
    }

    public void setOutput(String output) {
        this.output = output;
    }

    public PCode(PcodeOp pcodeOp) {
        id = Utils.PCodeId(pcodeOp);
        operation = PCodeOpNameCvt.get(pcodeOp.getOpcode());
        parent = pcodeOp.getParent().getStart().toString();

        for (var input : pcodeOp.getInputs()) {
            inputs.add(input.toString());
        }

        if (pcodeOp.getOutput() != null) {
            output = pcodeOp.getOutput().toString();
        }
    }
}
