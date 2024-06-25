package iotscope.symbolicsimulation;

import soot.jimple.Stmt;

public class Constraint {
    String operation;
    String left;
    String right;
    Stmt contextId;

    String left_base;
    String right_base;

    boolean negated =  false;

    public Constraint(String op, String le, String ri) {
        this.operation = op;
        this.left = le;
        this.right = ri;
        this.contextId = null;
        this.left_base = null;
        this.right_base = null;
    }

    public Constraint(String op, String le, String ri, Stmt cid) {
        this.operation = op;
        this.left = le;
        this.right = ri;
        this.contextId = cid;
        this.left_base = null;
        this.right_base = null;
    }

    public Constraint(String op, String le, String ri, String lbase, String rbase) {
        this.operation = op;
        this.left = le;
        this.right = ri;
        this.contextId = null;
        this.left_base = lbase;
        this.right_base = rbase;
    }

    public Constraint(String op, String le, String ri, Stmt cid, String lbase, String rbase) {
        this.operation = op;
        this.left = le;
        this.right = ri;
        this.contextId = cid;
        this.left_base = lbase;
        this.right_base = rbase;
    }
    
    public String getOperation() {
        return this.operation;
    }

    public String getLeft() {
        return this.left;
    }

    public String getRigh() {
        return this.right;
    }

    public Stmt getContextId() {
        return this.contextId;
    }

    public void setContextId(Stmt cid) {
        this.contextId = cid;
    }

    public Constraint clone(Stmt cid) {
        return new Constraint(this.operation, this.left, this.right, cid, this.left_base, this.right_base);
    }

    public Constraint clone() {
        return new Constraint(this.operation, this.left, this.right, this.contextId, this.left_base, this.right_base);
    }

    public boolean equals(Constraint c) {
        return (this.left.equals(c.left) && this.right.equals(c.right) && this.operation.equals(c.operation));
    }

    public String getLeftBase() {
        return this.left_base;
    }

    public String getRightBase() {
        return this.right_base;
    }

    public boolean isNegated() {
        return this.negated;
    }

    public Constraint negate(){
        Constraint tmp = this.clone();
        tmp.negated = true;
        return tmp;
    }
}
