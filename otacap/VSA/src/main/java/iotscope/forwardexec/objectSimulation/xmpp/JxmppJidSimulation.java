package iotscope.forwardexec.objectSimulation.xmpp;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;

public class JxmppJidSimulation implements SimulationObjects {


    private static final Logger LOGGER = LoggerFactory.getLogger(JxmppJidSimulation.class);


    public JxmppJidSimulation() {
    }

    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {

        return null;
    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (signature.contains("org.jxmpp.jid")) {
            HashSet<String> result = new HashSet<>();
            if (signature.startsWith("<org.jxmpp.jid.BareJid:") ||
                    signature.startsWith("<org.jxmpp.jid.DomainBareJid:") ||
                    signature.startsWith("<org.jxmpp.jid.DomainFullJid:") ||
                    signature.startsWith("<org.jxmpp.jid.DomainJid:") ||
                    signature.startsWith("<org.jxmpp.jid.EntityBareJid:") ||
                    signature.startsWith("<org.jxmpp.jid.EntityFullJid:") ||
                    signature.startsWith("<org.jxmpp.jid.EntityJid:") ||
                    signature.startsWith("<org.jxmpp.jid.FullJid:") ||
                    signature.startsWith("<org.jxmpp.jid.Jid:")) {
                if (stmt instanceof InstanceInvokeExpr) {
                    Value base = ((InstanceInvokeExpr) expr).getBase();
                    result = SimulationUtil.getStringContent(base, currentValues);
                }
            } else if (signature.startsWith("<org.jxmpp.jid.impl.JidCreate:") && (signature.contains("(java.lang.CharSequence)") || signature.contains("(java.lang.String)") || signature.contains("(org.jxmpp.jid.parts.Domainpart)"))) {
                result = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            } else if (signature.startsWith("<org.jxmpp.jid.impl.JidCreate:") &&
                    (
                            signature.contains("(org.jxmpp.jid.parts.Localpart,org.jxmpp.jid.DomainBareJid)") ||
                                    signature.contains("(org.jxmpp.jid.parts.Localpart,org.jxmpp.jid.Domainpart)") ||
                                    signature.contains("(org.jxmpp.jid.DomainBareJid,org.jxmpp.jid.parts.Resourcepart)") ||
                                    signature.contains("(org.jxmpp.jid.parts.Domainpart,org.jxmpp.jid.parts.Resourcepart)") ||
                                    signature.contains("(org.jxmpp.jid.parts.Localpart,org.jxmpp.jid.parts.Domainpart)")

                    )) {
                HashSet<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                HashSet<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues);
                Iterator<String> arg0Iter = arg0.iterator();
                Iterator<String> arg1Iter = arg1.iterator();
                while (arg0Iter.hasNext() || arg1Iter.hasNext()) {
                    String first = "";
                    String second = "";
                    if (arg0Iter.hasNext()) {
                        first = arg0Iter.next();
                    }
                    if (arg1Iter.hasNext()) {
                        second = arg1Iter.next();
                    }
                    result.add(first + second);
                }

            } else if (signature.startsWith("<org.jxmpp.jid.impl.JidCreate:") &&
                    (signature.contains("(org.jxmpp.jid.parts.Localpart,org.jxmpp.jid.DomainBareJid,org.jxmpp.jid.parts.Resourcepart)") ||
                            signature.contains("(org.jxmpp.jid.parts.Localpart,org.jxmpp.jid.parts.Domainpart,org.jxmpp.jid.parts.Resourcepart)") ||
                            signature.contains("(java.lang.String,java.lang.String,java.lang.String)") ||
                            signature.contains("(java.lang.CharSequence,java.lang.CharSequence,java.lang.CharSequence)"))) {
                HashSet<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                HashSet<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues);
                HashSet<String> arg2 = SimulationUtil.getStringContent(expr.getArg(2), currentValues);
                Iterator<String> arg0Iter = arg0.iterator();
                Iterator<String> arg1Iter = arg1.iterator();
                Iterator<String> arg2Iter = arg2.iterator();

                while (arg0Iter.hasNext() || arg1Iter.hasNext() || arg2Iter.hasNext()) {
                    String first = "";
                    String second = "";
                    String third = "";
                    if (arg0Iter.hasNext()) {
                        first = arg0Iter.next();
                    }
                    if (arg1Iter.hasNext()) {
                        second = arg1Iter.next();
                    }
                    if (arg2Iter.hasNext()) {
                        third = arg2Iter.next();
                    }
                    result.add(first + second + third);
                }

            } else if (signature.startsWith("<org.jxmpp.jid.parts.Localpart:") && signature.contains("from")) {
                result = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            } else if (signature.startsWith("<org.jxmpp.jid.parts.Domainpart:") && signature.contains("from")) {
                result = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            }else if (signature.startsWith("<org.jxmpp.jid.parts.Resourcepart:") && signature.contains("from")) {
                result = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            }
            return result;
        }
        return null;
    }


    @Override
    public HashSet<?> handleAssignConstant(AssignStmt stmt, Value rightValue, Value leftOp, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewArrayExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {

        return null;
    }

    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }


}
