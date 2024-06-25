package iotscope.forwardexec.objectSimulation.network;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.*;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.HashSet;

public class JavaNetUrlSimulation implements SimulationObjects {


    private static final Logger LOGGER = LoggerFactory.getLogger(JavaNetUrlSimulation.class);


    public JavaNetUrlSimulation() {
    }



    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<URL> url = new HashSet<>();
        if (signature.contains("java.net.URL")) {
            switch (signature) {
                case "<java.net.URL: void <init>(java.lang.String)>": {
                    HashSet<String> values = SimulationUtil.getStringContent(expr.getArg(0), currentValues);

                    values.forEach(v -> {
                        try {
                            if (!SimulationUtil.validProtocol(v)) {
                                v = SimulationUtil.addProtocolToString(v);
                            }
                            url.add(new URL(v));
                        } catch (MalformedURLException | NullPointerException e) {
                            try {
                                url.add(new URL(SimulationUtil.sanitizeURL(v)));
                            } catch (MalformedURLException | NullPointerException e2) {
                                LOGGER.error(e2.getLocalizedMessage());
                            }
                            //e.printStackTrace();
                        }
                    });
                }
                break;
                case "<java.net.URL: void <init>(java.lang.String,java.lang.String,int,java.lang.String)>": {
                    HashSet<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    HashSet<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues);
                    HashSet<Integer> arg2 = SimulationUtil.getIntContent(expr.getArg(2), currentValues);
                    HashSet<String> arg3 = SimulationUtil.getStringContent(expr.getArg(3), currentValues);


                    arg0.forEach(v1 -> {
                        arg1.forEach(v2 -> {
                            arg2.forEach(v3 -> {
                                arg3.forEach(v4 -> {
                                    try {
                                        String protocol = v1;
                                        if (!SimulationUtil.validProtocol(protocol)) {
                                            protocol = "unknown";
                                        }
                                        url.add(new URL(protocol, v2, v3, v4));
                                    } catch (MalformedURLException | NullPointerException e) {
                                        try {
                                            String protocol = v1;
                                            if (!SimulationUtil.validProtocol(protocol)) {
                                                protocol = "unknown";
                                            }
                                            url.add(new URL(protocol, SimulationUtil.findDomain(v2), v3, v4));
                                        } catch (MalformedURLException | NullPointerException e2) {
                                            LOGGER.error(e2.getLocalizedMessage());
                                        }
                                    }
                                });
                            });
                        });
                    });
                    break;
                }
                case "<java.net.URL: void <init>(java.lang.String,java.lang.String,int,java.lang.String,java.net.URLStreamHandler)>": {

                    HashSet<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    HashSet<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues);
                    HashSet<Integer> arg2 = SimulationUtil.getIntContent(expr.getArg(2), currentValues);
                    HashSet<String> arg3 = SimulationUtil.getStringContent(expr.getArg(3), currentValues);


                    arg0.forEach(v1 -> {
                        arg1.forEach(v2 -> {
                            arg2.forEach(v3 -> {
                                arg3.forEach(v4 -> {
                                    try {
                                        String protocol = v1;
                                        if (!SimulationUtil.validProtocol(protocol)) {
                                            protocol = "unknown";
                                        }
                                        url.add(new URL(protocol, v2, v3, v4));
                                    } catch (MalformedURLException | NullPointerException e) {
                                        try {
                                            String protocol = v1;
                                            if (!SimulationUtil.validProtocol(protocol)) {
                                                protocol = "unknown";
                                            }
                                            url.add(new URL(protocol, SimulationUtil.findDomain(v2), v3, v4));
                                        } catch (MalformedURLException | NullPointerException e2) {
                                            LOGGER.error(e2.getLocalizedMessage());
                                        }
                                    }
                                });
                            });
                        });
                    });
                    break;
                }
                case "<java.net.URL: void <init>(java.lang.String,java.lang.String,java.lang.String)>": {
                    HashSet<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    HashSet<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues);
                    HashSet<String> arg2 = SimulationUtil.getStringContent(expr.getArg(2), currentValues);

                    arg0.forEach(v1 -> {
                        arg1.forEach(v2 -> {
                            arg2.forEach(v3 -> {
                                try {
                                    String protocol = v1;
                                    if (!SimulationUtil.validProtocol(protocol)) {
                                        protocol = "unknown";
                                    }
                                    url.add(new URL(protocol, v2, v3));
                                } catch (MalformedURLException | NullPointerException e) {
                                    try {
                                        String protocol = v1;
                                        if (!SimulationUtil.validProtocol(protocol)) {
                                            protocol = "unknown";
                                        }
                                        url.add(new URL(protocol, SimulationUtil.findDomain(v2), v3));
                                    } catch (MalformedURLException | NullPointerException e2) {
                                        LOGGER.error(e2.getLocalizedMessage());
                                    }
                                }
                            });
                        });
                    });
                    break;
                }
                case "<java.net.URL: void <init>(java.net.URL,java.lang.String)>": {
                    HashSet<URL> arg0 = SimulationUtil.getJavaNetURL(expr.getArg(0), currentValues);
                    HashSet<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues);

                    arg0.forEach(v1 -> {
                        arg1.forEach(v2 -> {
                            try {
                                url.add(new URL(v1, v2));
                            } catch (MalformedURLException | NullPointerException e) {
                                //e.printStackTrace();
                                LOGGER.error(e.getLocalizedMessage());
                            }
                        });
                    });

                    break;
                }
                case "<java.net.URL: void <init>(java.net.URL,java.lang.String,java.net.URLStreamHandler)>": {
                    HashSet<URL> arg0 = SimulationUtil.getJavaNetURL(expr.getArg(0), currentValues);
                    HashSet<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues);


                    arg0.forEach(v1 -> {
                        arg1.forEach(v2 -> {
                            try {
                                url.add(new URL(v1, v2));
                            } catch (MalformedURLException | NullPointerException e) {
                                LOGGER.error(e.getLocalizedMessage());
                            }
                        });
                    });
                    break;
                }
            }
        }
        return url;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (signature.contains("java.net.URL")) {
            Value to = stmt.getLeftOp();
            HashSet<String> urlString = new HashSet<>();
            switch (signature) {
                case "<java.net.URL: java.lang.String toString()>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    if (currentValues.containsKey(to)) {
                        currentValues.get(to).clear();
                    }

                    HashSet<URL> urls = SimulationUtil.getJavaNetURL(from, currentValues);
                    urls.forEach(v -> {
                        urlString.add(v != null ? v.toString() : "");
                    });

                    break;
                }
                case "<java.net.URL: java.net.URI toURI()>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    HashSet<URI> uris = new HashSet<>();
                    if (currentValues.containsKey(to)) {
                        currentValues.get(to).clear();
                    }

                    HashSet<URL> urls = SimulationUtil.getJavaNetURL(from, currentValues);
                    urls.forEach(v -> {
                        try {
                            uris.add(v != null ? v.toURI() : null);
                        } catch (URISyntaxException e) {
                            //e.printStackTrace();
                            LOGGER.error(e.getLocalizedMessage());
                        }
                    });
                    return uris;

                }
                case "<java.net.URL: java.lang.String getHost()>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    if (currentValues.containsKey(to)) {
                        currentValues.get(to).clear();
                    }

                    HashSet<URL> urls = SimulationUtil.getJavaNetURL(from, currentValues);
                    urls.forEach(v -> {
                        urlString.add(v != null ? v.getHost() : null);
                    });

                    break;
                }
                case "<java.net.URL: java.lang.String getPath()>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    if (currentValues.containsKey(to)) {
                        currentValues.get(to).clear();
                    }

                    HashSet<URL> urls = SimulationUtil.getJavaNetURL(from, currentValues);
                    urls.forEach(v -> {
                        urlString.add(v != null ? v.getPath() : null);
                    });

                    break;
                }
                case "<java.net.URL: java.lang.String getAuthority()>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    if (currentValues.containsKey(to)) {
                        currentValues.get(to).clear();
                    }

                    HashSet<URL> urls = SimulationUtil.getJavaNetURL(from, currentValues);
                    urls.forEach(v -> {
                        urlString.add(v != null ? v.getAuthority() : null);
                    });

                    break;
                }
                case "<java.net.URL: java.lang.String getProtocol()>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    if (currentValues.containsKey(to)) {
                        currentValues.get(to).clear();
                    }

                    HashSet<URL> urls = SimulationUtil.getJavaNetURL(from, currentValues);
                    urls.forEach(v -> {
                        urlString.add(v != null ? v.getProtocol() : null);
                    });

                    break;
                }
                case "<java.net.URL: java.lang.String getQuery()>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    if (currentValues.containsKey(to)) {
                        currentValues.get(to).clear();
                    }

                    HashSet<URL> urls = SimulationUtil.getJavaNetURL(from, currentValues);
                    urls.forEach(v -> {
                        urlString.add(v != null ? v.getQuery() : null);
                    });

                    break;
                }
                case "<java.net.URL: java.lang.String getRef()>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    if (currentValues.containsKey(to)) {
                        currentValues.get(to).clear();
                    }

                    HashSet<URL> urls = SimulationUtil.getJavaNetURL(from, currentValues);
                    urls.forEach(v -> {
                        urlString.add(v != null ? v.getRef() : null);
                    });

                    break;
                }
                case "<java.net.URL: java.lang.String toExternalForm()>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    if (currentValues.containsKey(to)) {
                        currentValues.get(to).clear();
                    }

                    HashSet<URL> urls = SimulationUtil.getJavaNetURL(from, currentValues);
                    urls.forEach(v -> {
                        urlString.add(v != null ? v.toExternalForm() : null);
                    });

                    break;
                }
            }
            return urlString;
        }
        return null;
    }


    @Override
    public HashSet<?> handleAssignConstant(AssignStmt stmt, Value rightValue, Value leftOp, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewArrayExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        NewArrayExpr newArrayExpr = ((NewArrayExpr) rightValue);
        if (newArrayExpr.getBaseType().toString().equals("java.net.URL")) {
            return SimulationUtil.initArray(null, newArrayExpr, currentValues);
        }
        return null;
    }


    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }


}
