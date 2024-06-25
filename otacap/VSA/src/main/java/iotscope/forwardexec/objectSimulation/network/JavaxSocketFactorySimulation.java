package iotscope.forwardexec.objectSimulation.network;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;

import javax.net.SocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;

public class JavaxSocketFactorySimulation implements SimulationObjects {

    private static final Logger LOGGER = LoggerFactory.getLogger(JavaxSocketFactorySimulation.class);


    public JavaxSocketFactorySimulation() {
    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (signature.contains("javax.net.SocketFactory")) {
            HashSet<Socket> sockets = new HashSet<>();
            switch (signature) {
                case "<javax.net.SocketFactory: java.net.Socket createSocket()>": {
                    try {
                        sockets.add(SocketFactory.getDefault().createSocket());
                    } catch (IOException e) {
                        LOGGER.error("Could not create the socket");
                    }
                }
                break;
                case "<javax.net.SocketFactory: java.net.Socket createSocket(java.net.InetAddress,int)>": {
                    HashSet<InetAddress> addresses = SimulationUtil.getInetAddress(expr.getArg(0), currentValues);
                    HashSet<Integer> ports = SimulationUtil.getIntContent(expr.getArg(1), currentValues);
                    Iterator<InetAddress> addressIterator = addresses.iterator();
                    Iterator<Integer> integerIterator = ports.iterator();

                    try {
                        while (addressIterator.hasNext() && integerIterator.hasNext()) {
                            sockets.add(SocketFactory.getDefault().createSocket(addressIterator.next(), integerIterator.next()));
                        }
                    } catch (IOException e) {
                        LOGGER.error("Could not create the socket");
                    }
                }
                break;
                case "<javax.net.SocketFactory: java.net.Socket createSocket(java.net.InetAddress,int,java.net.InetAddress,int)>": {
                    HashSet<InetAddress> addresses = SimulationUtil.getInetAddress(expr.getArg(0), currentValues);
                    HashSet<Integer> ports = SimulationUtil.getIntContent(expr.getArg(1), currentValues);
                    HashSet<InetAddress> addresses2 = SimulationUtil.getInetAddress(expr.getArg(2), currentValues);
                    HashSet<Integer> ports2 = SimulationUtil.getIntContent(expr.getArg(3), currentValues);
                    Iterator<InetAddress> addressIterator = addresses.iterator();
                    Iterator<Integer> integerIterator = ports.iterator();
                    Iterator<InetAddress> addressIterator2 = addresses2.iterator();
                    Iterator<Integer> integerIterator2 = ports2.iterator();

                    try {
                        while (addressIterator.hasNext() && integerIterator.hasNext() && addressIterator2.hasNext() && integerIterator2.hasNext()) {
                            sockets.add(SocketFactory.getDefault().createSocket(addressIterator.next(), integerIterator.next(), addressIterator2.next(), integerIterator2.next()));
                        }
                    } catch (IOException e) {
                        LOGGER.error("Could not create the socket");
                    }

                }
                break;
                case "<javax.net.SocketFactory: java.net.Socket createSocket(java.lang.String,int)>": {
                    HashSet<String> addresses = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    HashSet<Integer> ports = SimulationUtil.getIntContent(expr.getArg(1), currentValues);
                    Iterator<String> addressIterator = addresses.iterator();
                    Iterator<Integer> integerIterator = ports.iterator();

                    try {
                        while (addressIterator.hasNext() && integerIterator.hasNext()) {
                            sockets.add(SocketFactory.getDefault().createSocket(addressIterator.next(), integerIterator.next()));
                        }
                    } catch (IOException e) {
                        LOGGER.error("Could not create the socket");
                    }
                }
                break;
                case "<javax.net.SocketFactory: java.net.Socket createSocket(java.lang.String,int.java.net.InetAddress,int)>": {
                    HashSet<String> addresses = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    HashSet<Integer> ports = SimulationUtil.getIntContent(expr.getArg(1), currentValues);
                    HashSet<InetAddress> addresses2 = SimulationUtil.getInetAddress(expr.getArg(2), currentValues);
                    HashSet<Integer> ports2 = SimulationUtil.getIntContent(expr.getArg(3), currentValues);
                    Iterator<String> addressIterator = addresses.iterator();
                    Iterator<Integer> integerIterator = ports.iterator();
                    Iterator<InetAddress> addressIterator2 = addresses2.iterator();
                    Iterator<Integer> integerIterator2 = ports2.iterator();

                    try {
                        while (addressIterator.hasNext() && integerIterator.hasNext() && addressIterator2.hasNext() && integerIterator2.hasNext()) {
                            sockets.add(SocketFactory.getDefault().createSocket(addressIterator.next(), integerIterator.next(), addressIterator2.next(), integerIterator2.next()));
                        }
                    } catch (IOException e) {
                        LOGGER.error("Could not create the socket");
                    }

                }
                break;
            }
            return sockets;
        }
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
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
