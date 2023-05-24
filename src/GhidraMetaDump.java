// Dumps the pcode into a nested json.
// @category PCode

import java.io.FileWriter;

import com.google.gson.GsonBuilder;

import entity.Metadata;
import ghidra.app.script.GhidraScript;

public class GhidraMetaDump extends GhidraScript {

    @Override
    public void run() throws Exception {
        var meta = new Metadata(currentProgram);

        var builder = new GsonBuilder();
        var gson = builder.create();
        var json = gson.toJson(meta);

        var file = askFile("Save file", "OK");
        if (file.createNewFile()) {
            println("New file is created");
        } else {
            println("File already exists, will be overwritten");
        }

        var writer = new FileWriter(file, false);
        writer.write(json);
        writer.close();
    }
}