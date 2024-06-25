package iotscope.utility;

import java.util.ArrayList;
import java.util.List;

import iotscope.symbolicsimulation.Constraint;
import soot.Value;
import soot.jimple.Stmt;

public class ConstraintUtil {

    private static final ConstraintUtil blockGenerator = new ConstraintUtil();

    public static ConstraintUtil getInstance() {
        return blockGenerator;
    }

    private ConstraintUtil() {
    }

    public static String getVarName(Value var) {
        if(var==null) {
            return null;
        }
        return "VAR:" + var + String.format("(%s)", var.hashCode());
    }

    public static Constraint createConstraint(String operation, Value left, Value right, Stmt contextId) {
        String op = operation;
        String leftOp = getVarName(left);
        String rightOp = getVarName(right);
        Constraint newConst = new Constraint(op, leftOp, rightOp, contextId);

        return newConst;
    }

    public static Constraint createConstraint(String operation, Value left, Value right) {
        String op = operation;
        String leftOp = getVarName(left);
        String rightOp = getVarName(right);
        Constraint newConst = new Constraint(op, leftOp, rightOp);

        return newConst;
    }

    public static Constraint createConstraint(String operation, Value left, String right) {
        String op = operation;
        String leftOp = getVarName(left);
        String rightOp = right;
        Constraint newConst = new Constraint(op, leftOp, rightOp);

        return newConst;
    }

    public static Constraint createConstraint(String operation, Value left, Value right, Value leftB, Value rightB) {
        String op = operation;
        String leftOp = getVarName(left);
        String rightOp = getVarName(right);
        String leftBase = getVarName(leftB);
        String rightBase = getVarName(rightB);

        Constraint newConst = new Constraint(op, leftOp, rightOp, leftBase, rightBase);

        return newConst;
    }


    public static List<List<Constraint>> makeCombinations(List<Constraint> consts) {
        List<List<Constraint>> result = new ArrayList<>();

        generateCombinations(consts, 0, new ArrayList<>(), result);

        return result;
    }

    private static void generateCombinations(List constraints, int index, List<Constraint> current, List<List<Constraint>> combinations) {
        if (index == constraints.size()) {
            combinations.add(new ArrayList<>(current));
            return;
        }
    
        Constraint currConst = (Constraint)constraints.get(index);
    
        // Add the current constraint and recurse
        current.add(currConst);
        generateCombinations(constraints, index + 1, current, combinations);
        current.remove(current.size() - 1);
    
        // Add the negated constraint if applicable and recurse
        if (!currConst.getOperation().equals("assign") && 
            !currConst.getOperation().equals("split") && 
            !currConst.getOperation().equals("concat")) {
            
            current.add(currConst.negate());
            generateCombinations(constraints, index + 1, current, combinations);
            current.remove(current.size() - 1);
        }
    }
    
}
