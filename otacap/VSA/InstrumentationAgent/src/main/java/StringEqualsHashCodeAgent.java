import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.CtNewMethod;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

public class StringEqualsHashCodeAgent implements ClassFileTransformer {

    // Add transformation
    @Override
    public byte[] transform(ClassLoader classLoader, String className, Class<?> aClass, ProtectionDomain protectionDomain, byte[] bytes) throws IllegalClassFormatException {
        String toStringMethod = "toString";
        String hashCodeMethod = "hashCode";
        String equalsMethod = "equals";

        String classNameReplaced = className.replace("/", ".");

        //Excluded classes part of the analysis and not the analyzed code
        if (classNameReplaced.startsWith("java.") || classNameReplaced.startsWith("sun.") ||
                classNameReplaced.startsWith("javax.") || classNameReplaced.startsWith("android.") ||
                classNameReplaced.startsWith("org.eclipse.") || classNameReplaced.startsWith("okhttp3.") ||
                classNameReplaced.startsWith("kotlinx.") || classNameReplaced.startsWith("kotlin.") ||
                classNameReplaced.startsWith("okio.") || classNameReplaced.startsWith("retrofit.") ||
                classNameReplaced.startsWith("androidx.") || classNameReplaced.startsWith("soot.") ||
                classNameReplaced.startsWith("com.sun.") || classNameReplaced.startsWith("jdk.") ||
                classNameReplaced.startsWith("org.javatuples.") || classNameReplaced.startsWith("heros.") ||
                classNameReplaced.startsWith("org.jf.dexlib2.") || classNameReplaced.startsWith("org.objectweb.") ||
                classNameReplaced.startsWith("rx.") || //com.bshg.homeconnect.android -> somehow dependency should be fixed...
                classNameReplaced.startsWith("com.google.") ||
                classNameReplaced.startsWith("pxb.android.") || classNameReplaced.startsWith("com.intellij.") ||
                classNameReplaced.startsWith("iotscope.") || classNameReplaced.startsWith("org.slf4j.") || classNameReplaced.startsWith("org.apache.")) {
            return bytes;
        }

        byte[] result = bytes;

        try {
            ClassPool classPool = ClassPool.getDefault();
            try {
                //Add jar files to class path
                String androidPath = classPool.getClassLoader().loadClass("iotscope.utility.ReflectionHelper").getField("androidJar").get(null).toString();
                String appPath = classPool.getClassLoader().loadClass("iotscope.utility.ReflectionHelper").getField("appJar").get(null).toString();
                if (androidPath != null) {
                    classPool.appendClassPath(androidPath);
                }
                if (appPath != null) {
                    classPool.appendClassPath(appPath);
                }
            }catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
                //Should not happen
            }

            CtClass ctClass = classPool.get(classNameReplaced);

            if (ctClass.isInterface()) {
                return bytes;
            }
            boolean overrideToString = true;
            boolean overrideHashCode = true;
            boolean overrideEquals = true;

            if (InstrumentationHelper.classImplementsToString(ctClass)) {
                overrideToString = false;
            }

            if (InstrumentationHelper.classImplementsHashCode(ctClass)) {
                overrideHashCode = false;
            }

            if (InstrumentationHelper.classImplementsEquals(ctClass)) {
                overrideEquals = false;
            }


            if (!overrideToString && !overrideHashCode && !overrideEquals) {
                return result;
            }

            if (overrideToString) {
                CtMethod newMethod = CtNewMethod.copy(classPool.get("ClassToCopy").getDeclaredMethod(toStringMethod), ctClass, null);
                ctClass.addMethod(newMethod);
            }
            if (overrideHashCode) {

                CtMethod newMethod = CtNewMethod.copy(classPool.get("ClassToCopy").getDeclaredMethod(hashCodeMethod), ctClass, null);
                ctClass.addMethod(newMethod);
            }
            if (overrideEquals) {
                CtMethod newMethod = CtNewMethod.copy(classPool.get("ClassToCopy").getDeclaredMethod(equalsMethod), ctClass, null);
                ctClass.addMethod(newMethod);
            }

            result = ctClass.toBytecode();
        } catch (Exception| Error e) {
            //Exception happened, however we cannot do much here
        }

        return result;
    }

    public static void premain(String args, Instrumentation inst) {
        //registers the transformer
        inst.addTransformer(new StringEqualsHashCodeAgent());
    }
}
