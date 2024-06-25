package iotscope.symbolicsimulation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.javatuples.Pair;
import org.sosy_lab.common.ShutdownManager;
import org.sosy_lab.common.configuration.Configuration;
import org.sosy_lab.common.configuration.InvalidConfigurationException;
import org.sosy_lab.common.log.BasicLogManager;
import org.sosy_lab.common.log.LogManager;
import org.sosy_lab.java_smt.SolverContextFactory;
import org.sosy_lab.java_smt.SolverContextFactory.Solvers;
import org.sosy_lab.java_smt.api.BooleanFormula;
import org.sosy_lab.java_smt.api.FormulaManager;
import org.sosy_lab.java_smt.api.Model;
import org.sosy_lab.java_smt.api.ProverEnvironment;
import org.sosy_lab.java_smt.api.SolverContext;
import org.sosy_lab.java_smt.api.SolverException;
import org.sosy_lab.java_smt.api.SolverContext.ProverOptions;
import org.sosy_lab.java_smt.api.StringFormula;
import org.sosy_lab.java_smt.api.StringFormulaManager;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SymbolicSolver {

    Configuration config;
    LogManager logger;
    ShutdownManager shutdown;

    SolverContext context;

    FormulaManager formManager;
    StringFormulaManager strManager;

    List<BooleanFormula> constraints;

    List<StringFormula> variables;

    HashMap<StringFormula, List<StringFormula>> arrayReferences;
    List<Pair<StringFormula, StringFormula>> splitValues;
    public SymbolicSolver() {

        variables = new ArrayList<>();
        constraints =  new ArrayList<>();

        arrayReferences =  new HashMap<>();
        splitValues = new ArrayList<>();

        try {

            config = Configuration.defaultConfiguration();
            logger = BasicLogManager.create(config);
            shutdown = ShutdownManager.create();
            context = SolverContextFactory.createSolverContext(config, logger, shutdown.getNotifier(), Solvers.Z3);

        } catch (InvalidConfigurationException e) {
            e.printStackTrace();
            throw new RuntimeException("Exception occurred ", e);
        }

        
        formManager = context.getFormulaManager();
        strManager = formManager.getStringFormulaManager();        
    }


    public String solve(String varStr) {
        String value = "";
        System.out.println("\nSOLVING");

        if( !this.arrayReferences.isEmpty() ) {
            addArrayConstraints();
        }

        try (ProverEnvironment prover = context.newProverEnvironment(ProverOptions.GENERATE_MODELS)) {
            try {
                System.out.println("Adding constraints");
                for(BooleanFormula c : constraints) {
                    System.out.println(c.toString());
                    prover.addConstraint(c);
                }
                boolean isUnsat = prover.isUnsat();
                if (!isUnsat) {
                    Model model = prover.getModel();
                    value = model.evaluate(addVariable(varStr.substring(4)));
                }
                
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (SolverException e) {
                e.printStackTrace();
            }
            
        }
        return value;
    }

    public StringFormula addVariable(String str) {
        System.out.println("Add var " + str);
        for(StringFormula a : variables) {
            System.out.println(a);
            if (a != null)
                if (a.toString().equals(str)){
                    return a;
                }
        }
        StringFormula toAdd = strManager.makeVariable(str);
        variables.add(toAdd);
        return toAdd;
    }


    public void addConstraint(String operation, Object left, Object right, Object leftBase, Object rightBase, boolean negated) {
        System.out.println("Add constraint: " + left + " " +operation+ " " + right);
        BooleanFormula constraint = null;
        StringFormula x = null;
        StringFormula y = null;
        
        switch (operation) {
            case "equals":
                if (negated) return;

                x = getValue((String)left);
                y = getValue((String)right);

                constraint = strManager.equal(x, y);
                break;

            case "assign":
                x = getValue((String)left);
                y = getValue((String)right);

                if(rightBase != null) {
                    if(leftBase == null)
                        arrayModel((String)left, (String)right, null, (String) rightBase);
                    else {
                        arrayModel((String)left, (String)right, (String)leftBase, (String) rightBase);
                    }
                }
                constraint = strManager.equal(x, y);
                break;

            case "contains":
                if (negated) return;
                x = getValue((String)left);
                y = getValue((String)right);
                constraint = strManager.contains(x, y);
                
                break;

            case "concat":
                if(right instanceof List){
                    List<StringFormula> rightList =  (List<StringFormula>)right;
                    x = (StringFormula) left;
                    StringFormula filler = null;

                    for(Pair<StringFormula, StringFormula> item : this.splitValues) {
                        if( ((StringFormula)item.getValue0()).equals(left)) {
                            filler = item.getValue1();
                        }
                    }

                    if(filler == null){
                        filler=strManager.makeString("");
                    }

                    List<StringFormula> toConcat = new ArrayList<>();
                    for(StringFormula item : rightList) {
                        toConcat.add(item);
                        if(rightList.indexOf(item) != rightList.size()-1) {
                            toConcat.add(filler);
                        }
                    }
                    y = strManager.concat(toConcat);
                    constraint = strManager.equal(x,y);
                }
                break;

            case "split":
                StringFormula newKey = getValue((String)left);    
                StringFormula splitValue = getValue((String) right);

                this.arrayReferences.put(newKey, new ArrayList<StringFormula>());

                Pair<StringFormula, StringFormula> pair = new Pair<StringFormula, StringFormula>(newKey, splitValue);
                this.splitValues.add(pair);
                break;

            case "starts":
                if (negated) return;
                x = getValue((String) left);    
                y = getValue((String) right);

                constraint = strManager.prefix(y, x);
                
                break;
            
            case "ends":
                if (negated) return;
                x = getValue((String) left);    
                y = getValue((String) right);
                constraint = strManager.suffix(y, x);
                
                break;
            
            default:
                break;
        }

        if(constraint != null) {
            constraints.add(constraint);
        }      
    }


    public StringFormula getValue(String str) {
        System.out.println("get value of " + str);
        StringFormula result = null;
        String tag = str.substring(0,4);
        String value = str.substring(4);
        if(tag.equals("VAR:")){
            result = addVariable(value);
        }
        else if(tag.equals("STR:")) {
            result = strManager.makeString(value);
        }
        return result;
    }
    
    public void arrayModel(String left, String right, String lbase, String rbase) {

        Pattern pattern = Pattern.compile("\\[(\\d+)\\]");

        Matcher l_matcher = pattern.matcher(left);
        Matcher r_matcher = pattern.matcher(right);

        if(l_matcher.find() && lbase != null) {
            List<StringFormula> tmp = new ArrayList<>();

            StringFormula leftFormula = getValue(left);
            StringFormula left_base = getValue(lbase);

            if(this.arrayReferences.containsKey(left_base)) {
                tmp = this.arrayReferences.get(left_base);
            }
            
            tmp.add(leftFormula);
            this.arrayReferences.put(left_base, tmp);

        }

        if(r_matcher.find() && rbase != null) {
            List<StringFormula> tmp = new ArrayList<>();

            StringFormula rightFormula = getValue(right);
            StringFormula right_base = getValue(rbase);

            if(this.arrayReferences.containsKey(right_base)) {
                tmp = this.arrayReferences.get(right_base);
            }

            tmp.add(rightFormula);
            this.arrayReferences.put(right_base, tmp);

        }
    }

    private void addArrayConstraints() {
        for( StringFormula key : this.arrayReferences.keySet()) {
            addConstraint("concat", key, this.arrayReferences.get(key), null, null, false);
        }
    }

}
