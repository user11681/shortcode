package user11681.shortcode;

import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.TypePath;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LocalVariableAnnotationNode;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TypeAnnotationNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import user11681.shortcode.instruction.MethodInvocation;
import user11681.shortcode.util.FrameStringMap;

@SuppressWarnings({"unused", "RedundantSuppression", "unchecked"})
public abstract class Shortcode implements Opcodes {
    public static final Object notFound = null;
    public static final int ABSTRACT_ALL = ACC_NATIVE | ACC_ABSTRACT;
    public static final int NA = 0;
    public static final int[] deltaStack = {
        0,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        2,
        2,
        1,
        1,
        1,
        2,
        2,
        1,
        1,
        1,
        NA,
        NA,
        1,
        2,
        1,
        2,
        1,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        -1,
        0,
        -1,
        0,
        -1,
        -1,
        -1,
        -1,
        -1,
        -2,
        -1,
        -2,
        -1,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        -3,
        -4,
        -3,
        -4,
        -3,
        -3,
        -3,
        -3,
        -1,
        -2,
        1,
        1,
        1,
        2,
        2,
        2,
        0,
        -1,
        -2,
        -1,
        -2,
        -1,
        -2,
        -1,
        -2,
        -1,
        -2,
        -1,
        -2,
        -1,
        -2,
        -1,
        -2,
        -1,
        -2,
        -1,
        -2,
        0,
        0,
        0,
        0,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -2,
        -1,
        -2,
        -1,
        -2,
        0,
        1,
        0,
        1,
        -1,
        -1,
        0,
        0,
        1,
        1,
        -1,
        0,
        -1,
        0,
        0,
        0,
        -3,
        -1,
        -1,
        -3,
        -3,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -2,
        -2,
        -2,
        -2,
        -2,
        -2,
        -2,
        -2,
        0,
        1,
        0,
        -1,
        -1,
        -1,
        -2,
        -1,
        -2,
        -1,
        0,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        1,
        0,
        0,
        0,
        NA,
        0,
        0,
        -1,
        -1,
        NA,
        NA,
        -1,
        -1,
        NA,
        NA
    };
    public static final String[] toString = {
        "nop",
        "aconst_null",
        "iconst_m1",
        "iconst_0",
        "iconst_1",
        "iconst_2",
        "iconst_3",
        "iconst_4",
        "iconst_5",
        "lconst_0",
        "lconst_1",
        "fconst_0",
        "fconst_1",
        "fconst_2",
        "dconst_0",
        "dconst_1",
        "bipush",
        "sipush",
        "ldc",
        "ldc_w",
        "ldc2_w",
        "iload",
        "lload",
        "fload",
        "dload",
        "aload",
        "iload_0",
        "iload_1",
        "iload_2",
        "iload_3",
        "lload_0",
        "lload_1",
        "lload_2",
        "lload_3",
        "fload_0",
        "fload_1",
        "fload_2",
        "fload_3",
        "dload_0",
        "dload_1",
        "dload_2",
        "dload_3",
        "aload_0",
        "aload_1",
        "aload_2",
        "aload_3",
        "iaload",
        "laload",
        "faload",
        "daload",
        "aaload",
        "baload",
        "caload",
        "saload",
        "istore",
        "lstore",
        "fstore",
        "dstore",
        "astore",
        "istore_0",
        "istore_1",
        "istore_2",
        "istore_3",
        "lstore_0",
        "lstore_1",
        "lstore_2",
        "lstore_3",
        "fstore_0",
        "fstore_1",
        "fstore_2",
        "fstore_3",
        "dstore_0",
        "dstore_1",
        "dstore_2",
        "dstore_3",
        "astore_0",
        "astore_1",
        "astore_2",
        "astore_3",
        "iastore",
        "lastore",
        "fastore",
        "dastore",
        "aastore",
        "bastore",
        "castore",
        "sastore",
        "pop",
        "pop2",
        "dup",
        "dup_x1",
        "dup_x2",
        "dup2",
        "dup2_x1",
        "dup2_x2",
        "swap",
        "iadd",
        "ladd",
        "fadd",
        "dadd",
        "isub",
        "lsub",
        "fsub",
        "dsub",
        "imul",
        "lmul",
        "fmul",
        "dmul",
        "idiv",
        "ldiv",
        "fdiv",
        "ddiv",
        "irem",
        "lrem",
        "frem",
        "drem",
        "ineg",
        "lneg",
        "fneg",
        "dneg",
        "ishl",
        "lshl",
        "ishr",
        "lshr",
        "iushr",
        "lushr",
        "iand",
        "land",
        "ior",
        "lor",
        "ixor",
        "lxor",
        "iinc",
        "i2l",
        "i2f",
        "i2d",
        "l2i",
        "l2f",
        "l2d",
        "f2i",
        "f2l",
        "f2d",
        "d2i",
        "d2l",
        "d2f",
        "i2b",
        "i2c",
        "i2s",
        "lcmp",
        "fcmpl",
        "fcmpg",
        "dcmpl",
        "dcmpg",
        "ifeq",
        "ifne",
        "iflt",
        "ifge",
        "ifgt",
        "ifle",
        "if_icmpeq",
        "if_icmpne",
        "if_icmplt",
        "if_icmpge",
        "if_icmpgt",
        "if_icmple",
        "if_acmpeq",
        "if_acmpne",
        "goto",
        "jsr",
        "ret",
        "tableswitch",
        "lookupswitch",
        "ireturn",
        "lreturn",
        "freturn",
        "dreturn",
        "areturn",
        "return",
        "getstatic",
        "putstatic",
        "getfield",
        "putfield",
        "invokevirtual",
        "invokespecial",
        "invokestatic",
        "invokeinterface",
        "invokedynamic",
        "new",
        "newarray",
        "anewarray",
        "arraylength",
        "athrow",
        "checkcast",
        "instanceof",
        "monitorenter",
        "monitorexit",
        "wide",
        "multianewarray",
        "ifnull",
        "ifnonnulL"
    };

    public static final String[] arrayTypeToString = {
        "T_BOOLEAN",
        "T_CHAR",
        "T_FLOAT",
        "T_DOUBLE",
        "T_BYTE",
        "T_SHORT",
        "T_INT",
        "T_LONG",
        };

    public static final FrameStringMap frameToString = new FrameStringMap();

    private static final HashMap<MethodInvocation, MethodNode> methodCache = new HashMap<>();

    public static String getInternalName(Class<?> klass) {
        return toInternalName(klass.getName());
    }

    public static String toInternalName(String name) {
        return fromDescriptor(name).replace('.', '/');
    }

    public static String getBinaryName(ClassNode klass) {
        return toBinaryName(klass.name);
    }

    public static String toBinaryName(String internalName) {
        return fromDescriptor(internalName).replace('/', '.');
    }

    public static String getDescriptor(Class<?> klass) {
        return toDescriptor(klass.getName());
    }

    public static String toDescriptor(String name) {
        switch (name) {
            case "V":
            case "Z":
            case "B":
            case "C":
            case "S":
            case "I":
            case "J":
            case "F":
            case "D":
                return name;
            default:
                name = name.charAt(0) == '['
                    ? '[' + toDescriptor(name.substring(1))
                    : name.charAt(name.length() - 1) == ';'
                        ? name
                        : "L" + name + ";";

                return name.replace('.', '/');
        }
    }

    public static String fromDescriptor(String descriptor) {
        if (descriptor.charAt(descriptor.length() - 1) == ';') {
            int LIndex = descriptor.indexOf('L');

            return descriptor.substring(0, LIndex) + descriptor.substring(LIndex + 1, descriptor.length() - 1);
        }

        return descriptor;
    }

    public static String getLocation(String name) {
        return toInternalName(name) + ".class";
    }

    public static String getPackage(String name) {
        String binaryName = toBinaryName(name);

        return binaryName.substring(0, binaryName.lastIndexOf('.'));
    }

    public static String getClassName(String name) {
        String binaryName = toBinaryName(name);

        return binaryName.substring(binaryName.lastIndexOf('.') + 1);
    }

    public static String[] getSupertypes(ClassNode klass) {
        int size = klass.interfaces.size();
        String[] supertypes = klass.interfaces.toArray(new String[size + 1]);
        supertypes[size] = klass.superName;

        return supertypes;
    }

    public static String composeMethodDescriptor(String returnType, String... parameterTypes) {
        StringBuilder descriptor = new StringBuilder().append('(');
        int parameterCount = parameterTypes.length;

        for (int i = 0; i != parameterCount; i++) {
            descriptor.append(toDescriptor(parameterTypes[i]));
        }

        return descriptor.append(')').append(toDescriptor(returnType)).toString();
    }

    public static void insertBeforeEveryReturn(MethodNode in, AbstractInsnNode instruction) {
        InsnList box = new InsnList();

        box.add(instruction);
    }

    public static void insertBeforeEveryReturn(MethodNode in, InsnList instructions) {
        LabelNode end = new LabelNode();
        int locals = in.maxLocals;
        AbstractInsnNode instruction = instructions.getFirst();

        while (instruction != null) {
            if (isReturn(instruction)) {
                in.instructions.insertBefore(instruction, copyInstructions(instructions));
            }

            instruction = instruction.getNext();
        }
    }

    public static InsnList inline(MethodInsnNode invocation) {
        return inline(getMethod(invocation), invocation);
    }

    public static InsnList inline(MethodInsnNode invocation, MethodNode in) {
        return inline(getMethod(invocation), in.instructions.getLast());
    }

    public static InsnList inline(MethodInsnNode invocation, InsnList in) {
        return inline(getMethod(invocation), in.getLast());
    }

    public static InsnList inline(MethodNode toInline, MethodNode in) {
        return inline(hasFlag(toInline.access, ACC_STATIC), toInline.instructions, Shortcode.getExplicitParameters(toInline), in.instructions.getLast());
    }

    public static InsnList inline(MethodNode toInline, InsnList in) {
        return inline(hasFlag(toInline.access, ACC_STATIC), toInline.instructions, Shortcode.getExplicitParameters(toInline), in.getLast());
    }

    public static InsnList inline(MethodNode toInline, AbstractInsnNode inlineStart) {
        return inline(hasFlag(toInline.access, ACC_STATIC), toInline.instructions, Shortcode.getExplicitParameters(toInline), inlineStart);
    }

    public static InsnList inline(boolean isStatic, InsnList instructions, List<String> parameters, AbstractInsnNode inlineStart) {
        final int parameterCount = parameters.size();
        final Map<Integer, Integer> newIndexes = new HashMap<>();
        final InsnList inlined = new InsnList();
        final int lastIndex = getNextVariableIndex(isStatic, inlineStart) + parameterCount - 1;
        int index = parameterCount - 1;
        int newIndex = lastIndex;

        for (int i = parameterCount - 1; i >= 0; i--, index--, newIndex--) {
            newIndexes.put(index, newIndex);

            inlined.add(new VarInsnNode(Shortcode.getStoreOpcode(parameters.get(i)), newIndex));
        }

        AbstractInsnNode instruction = instructions.getFirst();
        AbstractInsnNode previousReturn = null;
        LabelNode end = null;

        while (instruction != null) {
            if (Shortcode.isReturn(instruction)) {
                if (previousReturn != null) {
                    if (end == null) {
                        end = new LabelNode();
                    }

                    inlined.add(new JumpInsnNode(Opcodes.GOTO, end));
                }

                previousReturn = instruction;
            } else if (Shortcode.isLoad(instruction) || Shortcode.isStore(instruction)) {
                final VarInsnNode varInstruction = (VarInsnNode) Shortcode.clone(instruction);
                varInstruction.var = newIndexes.get(varInstruction.var);

                inlined.add(varInstruction);
            } else {
                inlined.add(Shortcode.clone(instruction));
            }

            instruction = instruction.getNext();
        }

        if (end != null) {
            inlined.add(end);
        }

        return inlined;
    }

    public static int getNextVariableIndex(final MethodNode method) {
        return getNextVariableIndex(hasFlag(method.access, ACC_STATIC), method.instructions.getLast());
    }

    public static int getNextVariableIndex(final boolean isStatic, final InsnList instructions) {
        return getNextVariableIndex(isStatic, instructions.getLast());
    }

    public static int getNextVariableIndex(final boolean isStatic, AbstractInsnNode instruction) {
        int index = -1;

        while (instruction != null && instruction.getType() != AbstractInsnNode.FRAME) {
            if (Shortcode.isStore(instruction)) {
                final int var = ((VarInsnNode) instruction).var;

                if (var > index) {
                    index = var;
                }
            }

            instruction = instruction.getPrevious();
        }

        if (index != -1) {
            return index + 1;
        }

        if (isStatic) {
            return 0;
        }

        return 1;
    }

    public static MethodNode copyMethod(ClassNode klass, MethodNode method) {
        method.accept(klass);

        return getFirstDeclaredMethod(klass, method.name);
    }

    public static InsnList copyInstructions(InsnList instructions) {
        return copyInstructions(instructions, new InsnList());
    }

    public static <T extends InsnList> T copyInstructions(InsnList instructions, T storage) {
        AbstractInsnNode instruction = instructions.getFirst();

        while (instruction != null) {
            storage.add(clone(instruction));

            instruction = instruction.getNext();
        }

        return storage;
    }

    public static List<? extends AbstractInsnNode> clone(List<? extends AbstractInsnNode> instructions) {
        return instructions.stream().map(Shortcode::clone).collect(Collectors.toList());
    }

    public static <T extends AbstractInsnNode> T[] clone(T... instructions) {
        return (T[]) Stream.of(instructions).map(Shortcode::clone).toArray();
    }

    public static <T extends AbstractInsnNode> T clone(T instruction) {
        switch (instruction.getType()) {
            case AbstractInsnNode.INSN:
                return (T) new InsnNode(instruction.getOpcode());
            case AbstractInsnNode.INT_INSN:
                return (T) new IntInsnNode(instruction.getOpcode(), ((IntInsnNode) instruction).operand);
            case AbstractInsnNode.VAR_INSN:
                return (T) new VarInsnNode(instruction.getOpcode(), ((VarInsnNode) instruction).var);
            case AbstractInsnNode.TYPE_INSN:
                return (T) new TypeInsnNode(instruction.getOpcode(), ((TypeInsnNode) instruction).desc);
            case AbstractInsnNode.FIELD_INSN:
                FieldInsnNode fieldInstruction = (FieldInsnNode) instruction;

                return (T) new FieldInsnNode(instruction.getOpcode(), fieldInstruction.owner, fieldInstruction.name, fieldInstruction.desc);
            case AbstractInsnNode.METHOD_INSN:
                MethodInsnNode methodInstruction = (MethodInsnNode) instruction;

                return (T) new MethodInsnNode(instruction.getOpcode(), methodInstruction.owner, methodInstruction.name, methodInstruction.desc, methodInstruction.itf);
            case AbstractInsnNode.INVOKE_DYNAMIC_INSN:
                InvokeDynamicInsnNode lambdaInstruction = (InvokeDynamicInsnNode) instruction;
                Object[] args = lambdaInstruction.bsmArgs;

                return (T) new InvokeDynamicInsnNode(lambdaInstruction.name, lambdaInstruction.desc, lambdaInstruction.bsm, Arrays.copyOf(args, args.length));
            case AbstractInsnNode.JUMP_INSN:
                return (T) new JumpInsnNode(instruction.getOpcode(), ((JumpInsnNode) instruction).label);
            case AbstractInsnNode.LABEL:
                return (T) new LabelNode(((LabelNode) instruction).getLabel());
            case AbstractInsnNode.LDC_INSN:
                return (T) new LdcInsnNode(((LdcInsnNode) instruction).cst);
            case AbstractInsnNode.IINC_INSN:
                IincInsnNode incrementation = (IincInsnNode) instruction;

                return (T) new IincInsnNode(incrementation.var, incrementation.incr);
            case AbstractInsnNode.TABLESWITCH_INSN:
                TableSwitchInsnNode tableSwitchNode = (TableSwitchInsnNode) instruction;

                return (T) new TableSwitchInsnNode(tableSwitchNode.min, tableSwitchNode.max, clone(tableSwitchNode.dflt), clone(tableSwitchNode.labels).toArray(new LabelNode[0]));
            case AbstractInsnNode.LOOKUPSWITCH_INSN:
                LookupSwitchInsnNode lookupSwitchNode = (LookupSwitchInsnNode) instruction;
                Object[] keyObjects = lookupSwitchNode.keys.toArray();
                int[] keys = new int[keyObjects.length];

                for (int i = 0; i < keyObjects.length; i++) {
                    keys[i] = (int) keyObjects[i];
                }

                return (T) new LookupSwitchInsnNode(clone(lookupSwitchNode.dflt), keys, clone(lookupSwitchNode.labels).toArray(new LabelNode[0]));
            case AbstractInsnNode.MULTIANEWARRAY_INSN:
                MultiANewArrayInsnNode arrayInstruction = (MultiANewArrayInsnNode) instruction;

                return (T) new MultiANewArrayInsnNode(arrayInstruction.desc, arrayInstruction.dims);
            case AbstractInsnNode.FRAME:
                FrameNode frameNode = (FrameNode) instruction;
                List<Object> local = frameNode.local;
                List<Object> stack = frameNode.stack;
                int localSize;
                Object[] localArray;
                int stackSize;
                Object[] stackArray;

                if (local == null) {
                    localSize = 0;
                    localArray = null;
                } else {
                    localSize = local.size();
                    localArray = local.toArray();
                }

                if (stack == null) {
                    stackSize = 0;
                    stackArray = null;
                } else {
                    stackSize = stack.size();
                    stackArray = stack.toArray();
                }

                return (T) new FrameNode(frameNode.getOpcode(), localSize, localArray, stackSize, stackArray);
            case AbstractInsnNode.LINE:
                LineNumberNode lineNode = (LineNumberNode) instruction;

                return (T) new LineNumberNode(lineNode.line, clone(lineNode.start));
        }

        throw new IllegalArgumentException(String.valueOf(instruction));
    }

    public static ClassNode getClassNode(Class<?> klass) {
        return getClassNode(klass.getName());
    }

    public static ClassNode getClassNode(String className) {
        try {
            ClassNode klass = new ClassNode();
            ClassReader reader = new ClassReader(className);

            reader.accept(klass, 0);

            return klass;
        } catch (IOException exception) {
            throw new RuntimeException(exception);
        }
    }

    public static ClassNode getClassNode(InputStream input) {
        try {
            ClassNode klass = new ClassNode();
            ClassReader reader = new ClassReader(input);

            reader.accept(klass, 0);

            return klass;
        } catch (IOException exception) {
            throw new RuntimeException(exception);
        }
    }

    public static LocalVariableNode getLocalVariable(MethodNode method, int index) {
        LocalVariableNode result = null;

        for (final LocalVariableNode local : method.localVariables) {
            if (index == local.index) {
                result = local;

                break;
            }
        }

        return result;
    }

    public static LocalVariableNode getLocalVariable(final MethodNode method, final String name) {
        LocalVariableNode result = null;

        for (final LocalVariableNode local : method.localVariables) {
            if (name.equals(local.name)) {
                result = local;

                break;
            }
        }

        return result;
    }

    public static InsnList getInstructions(final ClassNode klass, final String method) {
        return getInstructions(getFirstDeclaredMethod(klass, method));
    }

    public static InsnList getInstructions(final MethodNode method) {
        return method.instructions;
    }

    public static MethodNode getMethod(final MethodInsnNode invocation) {
        return getMethod(invocation, ClassLoader.getSystemClassLoader());
    }

    public static MethodNode getMethod(final MethodInsnNode invocation, final ClassLoader loader) {
        return getMethod(invocation, loader.getResourceAsStream(getLocation(invocation.owner)));
    }

    public static MethodNode getMethod(final MethodInsnNode invocation, final InputStream methodOwner) {
        return getMethod(invocation, getClassNode(methodOwner));
    }

    @SuppressWarnings("ConstantConditions")
    public static MethodNode getMethod(final MethodInsnNode invocation, final ClassNode methodOwner) {
        final MethodInvocation key = new MethodInvocation(invocation);
        final MethodNode method = methodCache.get(key);

        if (method == null) {
            try {
                final List<MethodNode> methods = methodOwner.methods;

                for (MethodNode node : methods) {
                    if (node.name.equals(invocation.name) && node.desc.equals(invocation.desc)) {
                        methodCache.put(key, node);

                        return node;
                    }
                }
            } catch (final Throwable throwable) {
                throw new RuntimeException(throwable);
            }
        }

        return method;
    }

    public static MethodNode getFirstMethod(ClassNode klass, final String name) {
        for (final MethodNode method : klass.methods) {
            if (name.equals(method.name)) {
                return method;
            }
        }

        if (klass.superName != null) {
            try {
                final ClassReader reader = new ClassReader(klass.superName);

                klass = new ClassNode();

                reader.accept(klass, 0);

                return getFirstMethod(klass, name);
            } catch (final IOException exception) {
                throw new RuntimeException(exception);
            }
        }

        return (MethodNode) notFound;
    }

    public static MethodNode getFirstDeclaredMethod(final ClassNode klass, final String name) {
        for (final MethodNode method : klass.methods) {
            if (name.equals(method.name)) {
                return method;
            }
        }

        return (MethodNode) notFound;
    }

    public static List<MethodNode> getAllMethods(ClassNode klass) {
        List<MethodNode> methods = new ArrayList<>();

        while (true) {
            methods.addAll(klass.methods);

            if (klass.superName != null) {
                try {
                    final ClassReader reader = new ClassReader(klass.superName);

                    klass = new ClassNode();

                    reader.accept(klass, 0);
                } catch (final IOException exception) {
                    throw new RuntimeException(exception);
                }
            } else {
                break;
            }
        }

        return methods;
    }

    public static List<MethodNode> getMethods(String internalClassName, String name) {
        return getMethods(getClassNode(internalClassName), name);
    }

    public static List<MethodNode> getMethods(ClassNode klass, String name) {
        final List<MethodNode> methods = new ArrayList<>();

        for (final MethodNode method : klass.methods) {
            if (name.equals(method.name)) {
                methods.add(method);
            }
        }

        return methods;
    }

    public static List<AbstractInsnNode> getInstructions(InsnList instructions, Predicate<AbstractInsnNode> condition) {
        List<AbstractInsnNode> matchingInstructions = new ArrayList<>();

        for (AbstractInsnNode instruction : instructions) {
            if (condition.test(instruction)) {
                matchingInstructions.add(instruction);
            }
        }

        return matchingInstructions;
    }

    public static int countExplicitParameters(InvokeDynamicInsnNode instruction) {
        return countExplicitParameters(instruction.desc);
    }

    public static int countExplicitParameters(MethodInsnNode instruction) {
        return countExplicitParameters(instruction.desc);
    }

    public static int countExplicitParameters(MethodNode method) {
        return countExplicitParameters(method.desc);
    }

    public static int countExplicitParameters(String descriptor) {
        String terminators = "VZCBSIJFD;";
        int end = descriptor.indexOf(')');
        int parameterCount = 0;
        int length = 0;
        char character;

        for (int i = descriptor.indexOf('(') + 1; i < end; ++i) {
            character = descriptor.charAt(i);
            ++length;

            if (terminators.indexOf(character) >= 0 && (length == 1 || character == ';' || length == 2 && descriptor.charAt(i - 1) == '[')) {
                ++parameterCount;
                length = 0;
            }
        }

        return parameterCount;
    }

    public static List<String> getExplicitParameters(final InvokeDynamicInsnNode instruction) {
        return getExplicitParameters(instruction.desc);
    }

    public static List<String> getExplicitParameters(final MethodInsnNode instruction) {
        return getExplicitParameters(instruction.desc);
    }

    public static List<String> getExplicitParameters(final MethodNode method) {
        return getExplicitParameters(method.desc);
    }

    public static List<String> getExplicitParameters(final String descriptor) {
        final List<String> parameters = new ArrayList<>();
        final int end = descriptor.indexOf(')');
        final StringBuilder parameter = new StringBuilder();
        final String primitives = "VZCBSIJFD";
        char character;

        for (int i = descriptor.indexOf('(') + 1; i < end; ++i) {
            character = descriptor.charAt(i);
            parameter.append(character);

            if (character == ';' || primitives.indexOf(character) >= 0 && (parameter.length() == 1 || parameter.length() == 2 && parameter.charAt(0) == '[')) {
                parameters.add(parameter.toString());
                parameter.delete(0, parameter.length());
            }
        }

        return parameters;
    }

    public static String getReturnType(final InvokeDynamicInsnNode instruction) {
        return getReturnType(instruction.desc);
    }

    public static String getReturnType(final MethodInsnNode instruction) {
        return getReturnType(instruction.desc);
    }

    public static String getReturnType(final MethodNode method) {
        return getReturnType(method.desc);
    }

    public static String getReturnType(final String descriptor) {
        return descriptor.substring(descriptor.indexOf(')') + 1);
    }

    public static List<String> parseDescriptor(final InvokeDynamicInsnNode instruction) {
        return parseDescriptor(instruction.desc);
    }

    public static List<String> parseDescriptor(final MethodInsnNode instruction) {
        return parseDescriptor(instruction.desc);
    }

    public static List<String> parseDescriptor(final MethodNode method) {
        return parseDescriptor(method.desc);
    }

    public static List<String> parseDescriptor(final String descriptor) {
        final List<String> types = new ArrayList<>();
        final int end = descriptor.indexOf(')');
        final String primitives = "VZCBSIJFD";
        final StringBuilder parameter = new StringBuilder();
        char character;

        for (int i = descriptor.indexOf('(') + 1; i < end; ++i) {
            character = descriptor.charAt(i);

            parameter.append(character);

            if (character == ';' || primitives.indexOf(character) >= 0 && (parameter.length() == 1 || parameter.length() == 2 && parameter.charAt(0) == '[')) {
                types.add(parameter.toString());

                parameter.delete(0, parameter.length());
            }
        }

        types.add(descriptor.substring(descriptor.indexOf(')') + 1));

        return types;
    }

    public static List<AnnotationNode> getRepeatableAnnotations(final List<AnnotationNode> annotations, final Class<? extends Annotation> repeatableType, final Class<? extends Annotation> container) {
        for (final AnnotationNode annotation : annotations) {
            if (annotation.desc.equals(getDescriptor(repeatableType))) {
                return Collections.singletonList(annotation);
            }

            if (annotation.desc.equals(getDescriptor(container))) {
                return getAnnotationValue(annotation, "value");
            }
        }

        return Collections.EMPTY_LIST;
    }

    public static <T> T getAnnotationValue(final List<AnnotationNode> annotations, final Class<? extends Annotation> type, final String element, final T alternative) {
        return getAnnotationValue(annotations, Type.getDescriptor(type), element, alternative);
    }

    public static <T> T getAnnotationValue(final List<AnnotationNode> annotations, final String annotationDescriptor, final String element, final T alternative) {
        Object[] values;

        for (int i = 0, size = annotations.size(); i < size; i++) {
            final AnnotationNode annotation = annotations.get(i);
            if (annotationDescriptor.equals(annotation.desc)) {
                values = annotation.values.toArray();

                for (int j = 0; j < values.length; j++) {
                    if (element.equals(values[j])) {
                        return (T) values[j + i];
                    }
                }

                return alternative;
            }
        }

        return null;
    }

    public static boolean hasAnnotation(final List<AnnotationNode> annotations, final Class<? extends Annotation> type) {
        return hasAnnotation(annotations, getDescriptor(type));
    }

    public static boolean hasAnnotation(final List<AnnotationNode> annotations, final String descriptor) {
        return getAnnotation(annotations, descriptor) != null;
    }

    public static AnnotationNode getAnnotation(final List<AnnotationNode> annotations, final Class<? extends Annotation> type) {
        return getAnnotation(annotations, getDescriptor(type));
    }

    public static AnnotationNode getAnnotation(final List<AnnotationNode> annotations, final String descriptor) {
        if (annotations != null) {
            for (final AnnotationNode annotation : annotations) {
                if (annotation.desc.equals(descriptor)) {
                    return annotation;
                }
            }

        }

        return (AnnotationNode) notFound;
    }

    public static <T> T getAnnotationValue(final AnnotationNode annotation, final String element, final T alternative) {
        final Object[] values = annotation.values.toArray();
        final int size = values.length;

        for (int i = 0; i < size; i += 2) {
            if (element.equals(values[i])) {
                return (T) values[i + 1];
            }
        }

        return alternative;
    }

    public static <T> T getAnnotationValue(final AnnotationNode annotation, final String element) {
        final Object[] values = annotation.values.toArray();
        final int size = values.length;

        for (int i = 0; i < size; i += 2) {
            if (element.equals(values[i])) {
                return (T) values[i + 1];
            }
        }

        throw new RuntimeException(String.format("cannot find the value of %s in %s", element, annotation));
    }

    public static Object getDefaultValue(final String descriptor) {
        switch (descriptor) {
            case "Z":
                return false;
            case "C":
                return (char) 0;
            case "B":
                return (byte) 0;
            case "S":
                return (short) 0;
            case "I":
                return 0;
            case "J":
                return 0L;
            case "F":
                return 0F;
            case "D":
                return 0D;
            default:
                return null;
        }
    }

    public static int getLoadOpcode(final String descriptor) {
        switch (descriptor) {
            case "Z":
            case "C":
            case "B":
            case "S":
            case "I":
                return ILOAD;
            case "J":
                return LLOAD;
            case "F":
                return FLOAD;
            case "D":
                return DLOAD;
            default:
                return ALOAD;
        }
    }

    public static int getStoreOpcode(final String descriptor) {
        switch (descriptor) {
            case "Z":
            case "C":
            case "B":
            case "S":
            case "I":
                return ISTORE;
            case "J":
                return LSTORE;
            case "F":
                return FSTORE;
            case "D":
                return DSTORE;
            default:
                return ASTORE;
        }
    }

    public static int getReturnOpcode(final MethodNode method) {
        return getReturnOpcode(getReturnType(method.desc));
    }

    public static int getReturnOpcode(final String descriptor) {
        switch (descriptor) {
            case "Z":
            case "C":
            case "B":
            case "S":
            case "I":
                return IRETURN;
            case "J":
                return LRETURN;
            case "F":
                return FRETURN;
            case "D":
                return DRETURN;
            case "V":
                return RETURN;
            default:
                return ARETURN;
        }
    }

    public static boolean isReturn(final AbstractInsnNode instruction) {
        return isReturn(instruction.getOpcode());
    }

    public static boolean isReturn(final int opcode) {
        switch (opcode) {
            case IRETURN:
            case LRETURN:
            case FRETURN:
            case DRETURN:
            case ARETURN:
            case RETURN:
                return true;
            default:
                return false;
        }
    }

    public static boolean isLoad(final AbstractInsnNode instruction) {
        return isLoad(instruction.getOpcode());
    }

    public static boolean isLoad(final int opcode) {
        switch (opcode) {
            case ILOAD:
            case LLOAD:
            case FLOAD:
            case DLOAD:
            case ALOAD:
                return true;
            default:
                return false;
        }
    }

    public static boolean isStore(final AbstractInsnNode instruction) {
        return isStore(instruction.getOpcode());
    }

    public static boolean isStore(final int opcode) {
        switch (opcode) {
            case ISTORE:
            case LSTORE:
            case FSTORE:
            case DSTORE:
            case ASTORE:
                return true;
            default:
                return false;
        }
    }

    public static boolean hasFlag(final int bitField, final int flag) {
        return (bitField & flag) != 0;
    }

    public static void findBackward(final ListIterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Runnable whenFound) {
        AbstractInsnNode instruction;

        while (iterator.hasPrevious()) {
            instruction = iterator.previous();

            if (condition.test(instruction)) {
                whenFound.run();

                return;
            }
        }

        throw new IllegalArgumentException("the specified predicate failed to apply");
    }

    public static void findBackward(final ListIterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Runnable whenFound, final Runnable alternative) {
        AbstractInsnNode instruction;

        while (iterator.hasPrevious()) {
            instruction = iterator.previous();

            if (condition.test(instruction)) {
                whenFound.run();

                return;
            }
        }

        alternative.run();
    }

    public static void findBackward(final ListIterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Consumer<AbstractInsnNode> whenFound) {
        AbstractInsnNode instruction;

        while (iterator.hasPrevious()) {
            instruction = iterator.previous();

            if (condition.test(instruction)) {
                whenFound.accept(instruction);

                return;
            }
        }
    }

    public static <T> T findBackward(final ListIterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Function<AbstractInsnNode, T> whenFound) {
        AbstractInsnNode instruction;

        while (iterator.hasPrevious()) {
            instruction = iterator.previous();

            if (condition.test(instruction)) {
                return whenFound.apply(instruction);
            }
        }

        throw new IllegalArgumentException("the specified predicate failed to apply");
    }

    public static void findBackward(final ListIterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Consumer<AbstractInsnNode> whenFound, final Runnable alternative) {
        AbstractInsnNode instruction;

        while (iterator.hasPrevious()) {
            instruction = iterator.previous();

            if (condition.test(instruction)) {
                whenFound.accept(instruction);

                return;
            }
        }

        alternative.run();
    }

    public static <T> T findForward(final Iterator<AbstractInsnNode> iterator, final AbstractInsnNode condition, final Supplier<T> whenFound) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (equals(condition, instruction)) {
                return whenFound.get();
            }
        }

        throw new IllegalArgumentException("the specified predicate failed to apply");
    }

    public static <T> T findForward(final Iterator<AbstractInsnNode> iterator, final AbstractInsnNode condition, final Supplier<T> whenFound, final Supplier<T> alternative) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (equals(condition, instruction)) {
                return whenFound.get();
            }
        }

        return alternative.get();
    }

    public static void findForward(final Iterator<AbstractInsnNode> iterator, final AbstractInsnNode condition, final Runnable whenFound) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (equals(condition, instruction)) {
                whenFound.run();

                return;
            }
        }

        throw new IllegalArgumentException("the specified predicate failed to apply");
    }

    public static void findForward(final Iterator<AbstractInsnNode> iterator, final AbstractInsnNode condition, final Runnable whenFound, final Runnable alternative) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (equals(condition, instruction)) {
                whenFound.run();

                return;
            }
        }

        alternative.run();
    }

    public static void findForward(final Iterator<AbstractInsnNode> iterator, final AbstractInsnNode condition, final Consumer<AbstractInsnNode> whenFound) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (equals(condition, instruction)) {
                whenFound.accept(instruction);

                return;
            }
        }
    }

    public static <T> T findForward(final Iterator<AbstractInsnNode> iterator, final AbstractInsnNode condition, final Function<AbstractInsnNode, T> whenFound) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (equals(condition, instruction)) {
                return whenFound.apply(instruction);
            }
        }

        throw new IllegalArgumentException("the specified predicate failed to apply");
    }

    public static void findForward(final Iterator<AbstractInsnNode> iterator, final AbstractInsnNode condition, final Consumer<AbstractInsnNode> whenFound, final Runnable alternative) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (equals(condition, instruction)) {
                whenFound.accept(instruction);

                return;
            }
        }

        alternative.run();
    }

    public static void findNForward(final Iterator<AbstractInsnNode> iterator, int n, final Predicate<AbstractInsnNode> condition, final Runnable whenFound) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (condition.test(instruction) && --n == 0) {
                whenFound.run();

                return;
            }
        }

        throw new IllegalArgumentException("the specified predicate failed to apply");
    }

    public static void findForward(final Iterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Runnable whenFound) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (condition.test(instruction)) {
                whenFound.run();

                return;
            }
        }

        throw new IllegalArgumentException("the specified predicate failed to apply");
    }

    public static void findForward(final Iterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Runnable whenFound, final Runnable alternative) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (condition.test(instruction)) {
                whenFound.run();

                return;
            }
        }

        alternative.run();
    }

    public static void findForward(final Iterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Consumer<AbstractInsnNode> whenFound) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (condition.test(instruction)) {
                whenFound.accept(instruction);

                return;
            }
        }
    }

    public static <T> T findForward(final Iterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Function<AbstractInsnNode, T> whenFound) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (condition.test(instruction)) {
                return whenFound.apply(instruction);
            }
        }

        throw new IllegalArgumentException("the specified predicate failed to apply");
    }

    public static <T> T findForward(final Iterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Supplier<T> whenFound) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (condition.test(instruction)) {
                return whenFound.get();
            }
        }

        throw new IllegalArgumentException("the specified predicate failed to apply");
    }

    public static void findForward(final Iterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Consumer<AbstractInsnNode> whenFound, final Runnable alternative) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (condition.test(instruction)) {
                whenFound.accept(instruction);

                return;
            }
        }

        alternative.run();
    }

    /**
     * remove instructions between the bounds specified by <b>{@code from}</b> and <b>{@code to}</b>
     *
     * @param iterator an iterator of the instruction list wherein to remove instructions
     * @param from     the {@linkplain AbstractInsnNode#getType() type} of the lower bound (inclusive) of the area to remove
     * @param to       the {@linkplain AbstractInsnNode#getType() type} of the upper bound (exclusive) of the area to remove
     */
    public static void removeBetween(final ListIterator<AbstractInsnNode> iterator, final int from, final int to) {
        while (iterator.previous().getType() != from) {
            iterator.remove();
        }

        iterator.remove();

        while (iterator.next().getType() != to) {
            iterator.remove();
        }
    }

    /**
     * remove instructions between the bounds specified by <b>{@code from}</b> and <b>{@code to}</b>
     *
     * @param iterator an iterator of the instruction list wherein to remove instructions
     * @param from     a predicate matching the lower bound (inclusive) of the area to remove
     * @param to       a predicate matching the upper bound (exclusive) of the area to remove
     */
    public static void removeBetween(final ListIterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> from, final Predicate<AbstractInsnNode> to) {
        AbstractInsnNode instruction = iterator.previous();

        while (!from.test(instruction)) {
            iterator.remove();

            instruction = iterator.previous();
        }

        iterator.remove();

        instruction = iterator.next();

        while (!to.test(instruction)) {
            iterator.remove();

            instruction = iterator.next();
        }
    }

    /**
     * remove instructions between the bounds specified by <b>{@code from}</b> and <b>{@code to}</b> inclusively
     *
     * @param iterator an iterator of the instruction list wherein to remove instructions
     * @param from     the {@linkplain AbstractInsnNode#getType() type} of the lower bound (inclusive) of the area to remove
     * @param to       the {@linkplain AbstractInsnNode#getType() type} of the upper bound (inclusive) of the area to remove
     */
    public static void removeBetweenInclusive(final ListIterator<AbstractInsnNode> iterator, final int from, final int to) {
        while (iterator.previous().getType() != from) {
            iterator.remove();
        }

        iterator.remove();

        while (iterator.next().getType() != to) {
            iterator.remove();
        }

        iterator.remove();
    }

    /**
     * remove instructions between the bounds specified by <b>{@code from}</b> and <b>{@code to}</b> inclusively
     *
     * @param iterator an iterator of the instruction list wherein to remove instructions
     * @param from     a predicate matching the lower bound (inclusive) of the area to remove
     * @param to       a predicate matching the upper bound (inclusive) of the area to remove
     */
    public static void removeBetweenInclusive(final ListIterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> from, final Predicate<AbstractInsnNode> to) {
        AbstractInsnNode instruction = iterator.previous();

        while (!from.test(instruction)) {
            iterator.remove();

            instruction = iterator.previous();
        }

        iterator.remove();

        instruction = iterator.next();

        while (!to.test(instruction)) {
            iterator.remove();

            instruction = iterator.next();
        }

        iterator.remove();
    }

    /**
     * remove instructions between the bounds specified by <b>{@code from}</b> and <b>{@code to}</b> exclusively
     *
     * @param iterator an iterator of the instruction list wherein to remove instructions
     * @param from     the {@linkplain AbstractInsnNode#getType() type} of the lower bound (exclusive) of the area to remove
     * @param to       the {@linkplain AbstractInsnNode#getType() type} of the upper bound (exclusive) of the area to remove
     */
    public static void removeBetweenExclusive(final ListIterator<AbstractInsnNode> iterator, final int from, final int to) {
        while (iterator.previous().getType() != from) {
            iterator.remove();
        }

        iterator.next();

        while (iterator.next().getType() != to) {
            iterator.remove();
        }
    }

    /**
     * remove instructions between the bounds specified by <b>{@code from}</b> and <b>{@code to}</b> exclusively
     *
     * @param iterator an iterator of the instruction list wherein to remove instructions
     * @param from     a predicate matching the lower bound (exclusive) of the area to remove
     * @param to       a predicate matching the upper bound (exclusive) of the area to remove
     */
    public static void removeBetweenExclusive(final ListIterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> from, final Predicate<AbstractInsnNode> to) {
        AbstractInsnNode instruction = iterator.previous();

        while (!from.test(instruction)) {
            iterator.remove();

            instruction = iterator.previous();
        }

        iterator.next();

        instruction = iterator.next();

        while (!to.test(instruction)) {
            iterator.remove();

            instruction = iterator.next();
        }
    }

    public static List<AbstractInsnNode> getInstructions(final InsnList instructions) {
        final List<AbstractInsnNode> list = new ArrayList<>();
        AbstractInsnNode instruction = instructions.getFirst();

        while (instruction != null) {
            list.add(instruction);

            instruction = instruction.getNext();
        }

        return list;
    }

    public static boolean equals(final Object object, final Object other) {
        if (object == other) {
            return true;
        }

        if (object == null) {
            return false;
        }

        if (object instanceof Object[] && other instanceof Object[]) {
            return equals((Object[]) object, (Object[]) other);
        }

        if (object instanceof List && other instanceof List) {
            return equals((List<?>) object, (List<?>) other);
        }

        if (object instanceof AbstractInsnNode && other instanceof AbstractInsnNode) {
            return equals((AbstractInsnNode) object, (AbstractInsnNode) other);
        }

        if (object instanceof AnnotationVisitor) {
            return equals((AnnotationVisitor) object, (AnnotationVisitor) other);
        }

        return Objects.equals(object, other);
    }

    public static boolean equals(final Object[] array, final Object[] other) {
        if (array == other) {
            return true;
        }

        if (array == null) {
            return false;
        }

        final int length = array.length;

        if (length != other.length) {
            return false;
        }

        for (int i = 0; i < length; i++) {
            if (!equals(array[i], other[i])) {
                return false;
            }
        }

        return true;
    }

    public static boolean equals(final List<?> list, final List<?> other) {
        if (list == other) {
            return true;
        }

        if (list == null) {
            return false;
        }

        final int size = list.size();

        if (size != other.size()) {
            return false;
        }

        for (int i = 0; i != size; i++) {
            if (!equals(list.get(i), other.get(i))) {
                return false;
            }
        }

        return true;
    }

    public static boolean equalsTypeAnnotations(final List<TypeAnnotationNode> annotations, final List<TypeAnnotationNode> other) {
        if (annotations == other) {
            return true;
        }

        if (annotations == null) {
            return false;
        }

        final int size = annotations.size();

        if (size != other.size()) {
            return false;
        }

        for (int i = 0; i != size; i++) {
            if (!equals(annotations.get(i), other.get(i))) {
                return false;
            }
        }

        return true;
    }

    public static boolean equals(final InsnList instructions, final InsnList otherInstructions) {
        return equals(instructions, otherInstructions, false);
    }

    public static boolean equals(final InsnList instructions, final InsnList otherInstructions, final boolean compareAnnotations) {
        if (instructions == otherInstructions) {
            return true;
        }

        if (instructions == null) {
            return false;
        }

        final int size = instructions.size();

        if (size != otherInstructions.size()) {
            return false;
        }

        AbstractInsnNode instruction = instructions.getFirst();
        AbstractInsnNode otherInstruction = otherInstructions.getFirst();

        while (instruction != null) {
            if (!equals(instruction, otherInstruction, compareAnnotations)) {
                return false;
            }

            instruction = instruction.getNext();
            otherInstruction = otherInstruction.getNext();
        }

        return true;
    }

    public static boolean equals(final AbstractInsnNode instruction, final AbstractInsnNode other) {
        return equals(instruction, other, false);
    }

    public static boolean equals(final AbstractInsnNode instruction, final AbstractInsnNode other, final boolean compareAnnotations) {
        if (instruction == other) {
            return true;
        }

        if (instruction == null) {
            return false;
        }

        final int opcode = instruction.getOpcode();
        final int otherOpcode = other.getOpcode();

        if (opcode != otherOpcode) {
            return false;
        }

        if (instruction.getType() == other.getType()) {
            if (compareAnnotations
                && (!equalsTypeAnnotations(instruction.invisibleTypeAnnotations, other.visibleTypeAnnotations)
                || !equalsTypeAnnotations(instruction.invisibleTypeAnnotations, other.visibleTypeAnnotations))) {
                return false;
            }

            switch (instruction.getType()) {
                case AbstractInsnNode.INSN:
                case AbstractInsnNode.LABEL:
                    return false;
                case AbstractInsnNode.INT_INSN:
                    return ((IntInsnNode) instruction).operand == ((IntInsnNode) other).operand;
                case AbstractInsnNode.VAR_INSN:
                    return ((VarInsnNode) instruction).var == ((VarInsnNode) other).var;
                case AbstractInsnNode.TYPE_INSN:
                    return Objects.equals(((TypeInsnNode) instruction).desc, ((TypeInsnNode) other).desc);
                case AbstractInsnNode.FIELD_INSN:
                    final FieldInsnNode fieldInstruction = (FieldInsnNode) instruction;
                    final FieldInsnNode otherFieldInstruction = (FieldInsnNode) other;

                    return Objects.equals(fieldInstruction.name, otherFieldInstruction.name)
                        && Objects.equals(fieldInstruction.desc, otherFieldInstruction.desc)
                        && Objects.equals(fieldInstruction.owner, otherFieldInstruction.owner);
                case AbstractInsnNode.METHOD_INSN:
                    final MethodInsnNode methodInstruction = (MethodInsnNode) instruction;
                    final MethodInsnNode otherMethodInstruction = (MethodInsnNode) other;

                    return Objects.equals(methodInstruction.name, otherMethodInstruction.name)
                        && Objects.equals(methodInstruction.owner, otherMethodInstruction.owner)
                        && Objects.equals(methodInstruction.desc, otherMethodInstruction.desc)
                        && methodInstruction.itf == otherMethodInstruction.itf;
                case AbstractInsnNode.INVOKE_DYNAMIC_INSN:
                    final InvokeDynamicInsnNode invokeDynamicInstruction = (InvokeDynamicInsnNode) instruction;
                    final InvokeDynamicInsnNode otherInvokeDynamicInstruction = (InvokeDynamicInsnNode) other;

                    return Objects.equals(invokeDynamicInstruction.name, otherInvokeDynamicInstruction.name)
                        && Objects.equals(invokeDynamicInstruction.desc, otherInvokeDynamicInstruction.desc)
                        && equals(invokeDynamicInstruction.bsmArgs, otherInvokeDynamicInstruction.bsmArgs);
                case AbstractInsnNode.JUMP_INSN:
                    return ((JumpInsnNode) instruction).label.getLabel() == ((JumpInsnNode) other).label.getLabel();
                case AbstractInsnNode.LDC_INSN:
                    return Objects.equals(((LdcInsnNode) instruction).cst, ((LdcInsnNode) other).cst);
                case AbstractInsnNode.IINC_INSN:
                    final IincInsnNode iIncInstruction = (IincInsnNode) instruction;
                    final IincInsnNode otherIIncInstruction = (IincInsnNode) other;

                    return iIncInstruction.var == otherIIncInstruction.var && iIncInstruction.incr == otherIIncInstruction.incr;
                case AbstractInsnNode.TABLESWITCH_INSN: {
                    final TableSwitchInsnNode tableSwitchInstruction = (TableSwitchInsnNode) instruction;
                    final TableSwitchInsnNode otherTableSwitchInstruction = (TableSwitchInsnNode) other;

                    if (!(tableSwitchInstruction.min == otherTableSwitchInstruction.min
                        && tableSwitchInstruction.max == otherTableSwitchInstruction.max
                        && tableSwitchInstruction.dflt.getLabel() == otherTableSwitchInstruction.dflt.getLabel())) {
                        return false;
                    }

                    final List<LabelNode> labels = tableSwitchInstruction.labels;
                    final List<LabelNode> otherLabels = otherTableSwitchInstruction.labels;

                    final int size = labels.size();

                    if (size != otherLabels.size()) {
                        return false;
                    }

                    for (int i = 0; i != size; i++) {
                        if (labels.get(i) != otherLabels.get(i)) {
                            return false;
                        }
                    }

                    return true;
                }
                case AbstractInsnNode.LOOKUPSWITCH_INSN: {
                    final LookupSwitchInsnNode lookupSwitchInstruction = (LookupSwitchInsnNode) instruction;
                    final LookupSwitchInsnNode otherLookupSwitchInstruction = (LookupSwitchInsnNode) other;

                    if (!(lookupSwitchInstruction.dflt.getLabel() == otherLookupSwitchInstruction.dflt.getLabel())) {
                        return false;
                    }

                    if (!lookupSwitchInstruction.keys.equals(otherLookupSwitchInstruction.keys)) {
                        return false;
                    }

                    final List<LabelNode> labels = lookupSwitchInstruction.labels;
                    final List<LabelNode> otherLabels = otherLookupSwitchInstruction.labels;

                    final int size = labels.size();

                    if (size != otherLabels.size()) {
                        return false;
                    }

                    for (int i = 0; i != size; i++) {
                        if (labels.get(i) != otherLabels.get(i)) {
                            return false;
                        }
                    }

                    return true;
                }
                case AbstractInsnNode.MULTIANEWARRAY_INSN:
                    final MultiANewArrayInsnNode multiANewArrayInstruction = (MultiANewArrayInsnNode) instruction;
                    final MultiANewArrayInsnNode otherMultiANewArrayInstruction = (MultiANewArrayInsnNode) other;

                    return multiANewArrayInstruction.desc.equals(otherMultiANewArrayInstruction.desc);
                case AbstractInsnNode.FRAME:
                    final FrameNode frame = (FrameNode) instruction;
                    final FrameNode otherFrame = (FrameNode) other;

                    return frame.type == otherFrame.type && frame.stack.equals(otherFrame.stack) && frame.local.equals(otherFrame.stack);
                case AbstractInsnNode.LINE:
                    final LineNumberNode line = (LineNumberNode) instruction;
                    final LineNumberNode otherLine = (LineNumberNode) other;

                    return line.line == otherLine.line && line.start.getLabel() == otherLine.start.getLabel();
            }
        }

        return false;
    }

    public static boolean equals(final LocalVariableAnnotationNode annotation, final LocalVariableAnnotationNode other) {
        return equals((TypeAnnotationNode) annotation, other) && Objects.equals(annotation.start, other.start) && Objects.equals(annotation.end, other.end) && Objects.equals(annotation.index, other.index);
    }

    public static boolean equals(final TypeAnnotationNode annotation, final TypeAnnotationNode other) {
        if (annotation.typeRef != other.typeRef) {
            return false;
        }

        final TypePath path = annotation.typePath;
        final TypePath otherPath = other.typePath;

        if (path != null && otherPath != null) {
            final int length = path.getLength();

            if (length != otherPath.getLength()) {
                return false;
            }

            for (int i = 0; i != length; i++) {
                if (path.getStep(i) != otherPath.getStep(i)) {
                    return false;
                }
            }
        }

        return equals((AnnotationNode) annotation, other);
    }

    public static boolean equals(final AnnotationNode annotation, final AnnotationNode other) {
        return Objects.equals(annotation.desc, other.desc) && equals(annotation.values, other.values);
    }

    public static boolean equals(final AnnotationVisitor annotation, final AnnotationVisitor other) {
        if (annotation == other) {
            return true;
        }

        if (annotation == null) {
            return false;
        }

        final Class<? extends AnnotationVisitor> klass = annotation.getClass();

        if (klass != other.getClass()) {
            return false;
        }

        if (klass == AnnotationNode.class) {
            return equals((AnnotationNode) annotation, (AnnotationNode) other);
        } else if (klass == TypeAnnotationNode.class) {
            return equals((TypeAnnotationNode) annotation, (TypeAnnotationNode) other);
        } else if (klass == LocalVariableAnnotationNode.class) {
            return equals((LocalVariableAnnotationNode) annotation, (LocalVariableAnnotationNode) other);
        } else {
            return annotation.equals(other);
        }
    }
}
