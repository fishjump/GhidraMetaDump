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

        var tbl = program.getSymbolTable();

        for (var func : program.getFunctionManager().getFunctions(/* forward: */ false)) {
            var res = ifc.decompileFunction(func, 30, null);

            if (!res.decompileCompleted()) {
                printf("Decompile failed for %s\n", func.getName());
                continue;
            }

            // if (!func.getName().equals("main")) {
            // continue;
            // }

            var hF = res.getHighFunction();
            if (hF == null) {
                continue;
            }

            printf("Name: %s\n", hF.getFunction().getName());
            printf("  entry: 0x%s\n", func.getBody().getMinAddress());
            printf("  exit: 0x%s\n", func.getBody().getMaxAddress());

            print("  local symbols:\n");
            res.getHighFunction().getLocalSymbolMap().getSymbols().forEachRemaining((symbol) -> {
                printf("    name:  %s\n", symbol.getName());
                printf("    type:  %s\n", symbol.getDataType());
                printf("    addr:  0x%s\n", symbol.getPCAddress());
                if (symbol.getHighVariable() != null) {
                    var hV = symbol.getHighVariable();
                    printf("    reps:  %s\n", hV.getRepresentative());
                    print("    varnodes:\n");
                    for (var vnode : hV.getInstances()) {
                        printf("      addr: %s, pcode: %s\n", vnode.getPCAddress(), vnode);
                    }
                }
            });

            print("  global symbols:\n");
            res.getHighFunction().getGlobalSymbolMap().getSymbols().forEachRemaining((symbol) -> {
                printf("    name:  %s\n", symbol.getName());
                printf("    type:  %s\n", symbol.getDataType());
                printf("    addr:  0x%s\n", symbol.getPCAddress());
                if (symbol.getHighVariable() != null) {
                    var hV = symbol.getHighVariable();
                    printf("    reps:  %s\n", hV.getRepresentative());
                    print("    varnodes:\n");
                    for (var vnode : hV.getInstances()) {
                        printf("      addr: %s, pcode: %s\n", vnode.getPCAddress(), vnode);
                    }
                }
            });


        }
    }
}