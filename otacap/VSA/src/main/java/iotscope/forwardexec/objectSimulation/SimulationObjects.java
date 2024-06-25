package iotscope.forwardexec.objectSimulation;

import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;

import java.util.HashMap;
import java.util.HashSet;

public interface SimulationObjects {

    HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues);

    HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues);

    HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues);

    HashSet<?> handleAssignConstant(AssignStmt stmt, Value rightValue, Value leftOp, HashMap<Value, HashSet<?>> currentValues);

    HashSet<?> handleAssignNewArrayExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues);

    HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues);
}
