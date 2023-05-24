package entity;

import ghidra.program.model.pcode.HighSymbol;

public class Symbol {
    public String id;
    public String dataType;
    public Integer length;
    public Boolean isPointer;

    public String representative;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getDataType() {
        return dataType;
    }

    public void setDataType(String dataType) {
        this.dataType = dataType;
    }

    public Integer getLength() {
        return length;
    }

    public void setLength(Integer length) {
        this.length = length;
    }

    public Boolean getIsPointer() {
        return isPointer;
    }

    public void setIsPointer(Boolean isPointer) {
        this.isPointer = isPointer;
    }

    public String getRepresentative() {
        return representative;
    }

    public void setRepresentative(String representative) {
        this.representative = representative;
    }

    public Symbol(HighSymbol symbol) {
        id = symbol.getName();
        dataType = symbol.getDataType().toString();
        length = symbol.getDataType().getLength();
        isPointer = symbol.getDataType() instanceof ghidra.program.model.data.Pointer;

        if (symbol.getHighVariable() != null) {
            representative = symbol.getHighVariable().getRepresentative().toString();
        }
    }
}
