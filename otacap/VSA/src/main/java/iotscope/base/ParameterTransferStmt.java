package iotscope.base;

import soot.*;
import soot.jimple.ArrayRef;
import soot.jimple.AssignStmt;
import soot.jimple.FieldRef;
import soot.jimple.InvokeExpr;
import soot.jimple.internal.VariableBox;
import soot.tagkit.Host;
import soot.tagkit.Tag;
import soot.util.Switch;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class ParameterTransferStmt implements AssignStmt {

    private final Value left;
    private final Value right;

    public ParameterTransferStmt(Value left, Value right) {
        super();
        this.left = left;
        this.right = right;
    }

    @Override
    public String toString() {
        return String.format("%s = %s", left, right);
    }

    @Override
    public Value getLeftOp() {
        return left;
    }

    @Override
    public Value getRightOp() {
        return right;
    }

    @Override
    public ValueBox getLeftOpBox() {
        return null;
    }

    @Override
    public ValueBox getRightOpBox() {
        return null;
    }

    @Override
    public void toString(UnitPrinter up) {

    }

    @Override
    public boolean containsInvokeExpr() {
        return false;
    }

    @Override
    public InvokeExpr getInvokeExpr() {
        return null;
    }

    @Override
    public ValueBox getInvokeExprBox() {
        return null;
    }

    @Override
    public boolean containsArrayRef() {
        return false;
    }

    @Override
    public ArrayRef getArrayRef() {
        return null;
    }

    @Override
    public ValueBox getArrayRefBox() {
        return null;
    }

    @Override
    public boolean containsFieldRef() {
        return false;
    }

    @Override
    public FieldRef getFieldRef() {
        return null;
    }

    @Override
    public ValueBox getFieldRefBox() {
        return null;
    }

    @Override
    public List<ValueBox> getUseBoxes() {
        return null;
    }

    @Override
    public List<ValueBox> getDefBoxes() {
        return null;
    }

    @Override
    public List<UnitBox> getUnitBoxes() {
        return null;
    }

    @Override
    public List<UnitBox> getBoxesPointingToThis() {
        return null;
    }

    @Override
    public void addBoxPointingToThis(UnitBox b) {

    }

    @Override
    public void removeBoxPointingToThis(UnitBox b) {

    }

    @Override
    public void clearUnitBoxes() {
    }

    @Override
    public List<ValueBox> getUseAndDefBoxes() {
        // JValueBox a = new ValueBox();
        List<ValueBox> ret = new ArrayList<>();
        ret.add(new LinkedVariableBox(left));
        ret.add(new LinkedVariableBox(right));
        return ret;
    }

    private static class LinkedVariableBox extends VariableBox {
        /**
         *
         */
        private static final long serialVersionUID = 1L;

        private LinkedVariableBox(Value v) {
            super(v);
        }

        @Override
        public boolean canContainValue(Value v) {
            return true;
        }
    }

    @Override
    public boolean fallsThrough() {
        return false;
    }

    @Override
    public boolean branches() {
        return false;
    }

    @Override
    public void redirectJumpsToThisTo(Unit newLocation) {

    }

    @Override
    public void apply(Switch sw) {

    }

    @Override
    public List<Tag> getTags() {
        return null;
    }

    @Override
    public Tag getTag(String aName) {
        return null;
    }

    @Override
    public void addTag(Tag t) {

    }

    @Override
    public void removeTag(String name) {

    }

    @Override
    public boolean hasTag(String aName) {
        return false;
    }

    @Override
    public void removeAllTags() {

    }

    @Override
    public void addAllTagsOf(Host h) {

    }

    @Override
    public int getJavaSourceStartLineNumber() {
        return 0;
    }

    @Override
    public int getJavaSourceStartColumnNumber() {
        return 0;
    }

    @Override
    public void setLeftOp(Value variable) {

    }

    @Override
    public void setRightOp(Value rvalue) {

    }

    @Override
    public ParameterTransferStmt clone() {
        return new ParameterTransferStmt(this.getLeftOp(), this.getRightOp());
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ParameterTransferStmt that = (ParameterTransferStmt) o;
        return Objects.equals(left, that.left) && Objects.equals(right, that.right);
    }

    @Override
    public int hashCode() {
        return Objects.hash(left, right);
    }
}
