// Dumps the pcode into a nested json.
// @category PCode

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;

public class GhidraMetaDump extends GhidraScript {

    @Override
    public void run() throws Exception {
        var program = currentProgram;

        var ifc = new DecompInterface();
        var options = new DecompileOptions();
        ifc.setOptions(options);
        ifc.openProgram(program);

        for (var func : program.getFunctionManager().getFunctions(/* forward: */ true)) {
            var res = ifc.decompileFunction(func, 30, null);
            var hF = res.getHighFunction();

            if (hF == null) {
                continue;
            }

            printf("%s\n", hF.getFunction().getName());
        }
    }
}