package iotscope.backwardslicing;

import java.util.ArrayList;
import java.util.List;

public class BackwardRule {
    private boolean isBaseInteresting;
    private List<Integer> interestingArgs;
    private boolean taintAll;
    private List<String> except;
    private List<String> sysApiSrc;

    public BackwardRule() {
        isBaseInteresting = false;
        interestingArgs = new ArrayList<>();
        except = new ArrayList<>();
        sysApiSrc = new ArrayList<>();
    }

    public boolean isBaseInteresting() {
        return isBaseInteresting;
    }

    public void setBaseInteresting(boolean baseInteresting) {
        isBaseInteresting = baseInteresting;
    }

    public List<Integer> getInterestingArgs() {
        return interestingArgs;
    }

    public void setInterestingArgs(List<Integer> interestingArgs) {
        this.interestingArgs = interestingArgs;
    }

    public List<String> getExcept() {
        return except;
    }

    public void setExcept(List<String> except) {
        this.except = except;
    }

    public boolean isTaintAll() {
        return taintAll;
    }

    public void setTaintAll(boolean taintAll) {
        this.taintAll = taintAll;
    }

    public void setSysApiSrc(List<String> sysApiSrc) {
        this.sysApiSrc = sysApiSrc;
    }
}
