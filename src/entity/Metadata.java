package entity;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.listing.Program;

public class Metadata {
    public List<Function> functions = new ArrayList<>();

    public List<Function> getFunctions() {
        return functions;
    }

    public void setFunctions(List<Function> functions) {
        this.functions = functions;
    }

    public Metadata(Program program) {
        var dIf = new DecompInterface();
        var options = new DecompileOptions();
        dIf.setOptions(options);
        dIf.openProgram(program);

        for (var func : program.getFunctionManager().getFunctions(/* forwarwd: */false)) {
            if (func.isThunk()) {
                continue;
            }

            var res = dIf.decompileFunction(func, 30, null);

            if (!res.decompileCompleted()) {
                continue;
            }

            var hF = res.getHighFunction();

            if (hF == null) {
                continue;
            }

            var function = new Function(hF);
            functions.add(function);
        }
    }
}
