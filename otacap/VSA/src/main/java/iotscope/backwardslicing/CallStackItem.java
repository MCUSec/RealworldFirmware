package iotscope.backwardslicing;

import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.toolkits.graph.Block;

public class CallStackItem {
    private SootMethod sootMethod;
    private Block block;
    private Unit currentInstruction;
    private Value returnTarget;

    public CallStackItem(SootMethod sootMethod, Block block, Unit currentInstruction, Value returnTarget) {
        this.sootMethod = sootMethod;
        this.block = block;
        this.currentInstruction = currentInstruction;
        this.returnTarget = returnTarget;
    }

    public SootMethod getSootMethod() {
        return sootMethod;
    }

    public void setSootMethod(SootMethod sootMethod) {
        this.sootMethod = sootMethod;
    }

    public Block getBlock() {
        return block;
    }

    public void setBlock(Block block) {
        this.block = block;
    }

    public Unit getCurrentInstruction() {
        return currentInstruction;
    }

    public void setCurrentInstruction(Unit currentInstruction) {
        this.currentInstruction = currentInstruction;
    }

    public Value getReturnTarget() {
        return returnTarget;
    }

    public void setReturnTarget(Value returnTarget) {
        this.returnTarget = returnTarget;
    }
}
