package user11681.shortcode.instruction;

import java.util.HashMap;
import java.util.function.Function;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
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
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

@SuppressWarnings("unused")
public final class ExtendedInsnList extends InsnList {
    private static final Function<String, Label> labelConstructor = label -> new Label();

    private final HashMap<String, Label> labels = new HashMap<>();

    public ExtendedInsnList() {}

    public ExtendedInsnList(AbstractInsnNode... instructions) {
        this.add(instructions);
    }

    public ExtendedInsnList(InsnList instructions) {
        super.add(instructions);
    }

    private static Object[] getLabelNodes(Object[] objects) {
        final Object[] labelNodes = new Object[objects.length];
        Object object;

        for (int i = 0, n = objects.length; i < n; ++i) {
            object = objects[i];

            if (object instanceof Label) {
                object = getLabelNode((Label) object);
            }

            labelNodes[i] = object;
        }

        return labelNodes;
    }

    private static LabelNode[] getLabelNodes(Label[] labels) {
        final LabelNode[] labelNodes = new LabelNode[labels.length];

        for (int i = 0, n = labels.length; i < n; ++i) {
            labelNodes[i] = getLabelNode(labels[i]);
        }

        return labelNodes;
    }

    private static LabelNode getLabelNode(Label label) {
        return (LabelNode) (label.info == null ? label.info = new LabelNode() : label.info);
    }

    public final ExtendedInsnList append(AbstractInsnNode instruction) {
        super.add(instruction);

        return this;
    }

    public final void add(AbstractInsnNode... instructions) {
        for (AbstractInsnNode instruction : instructions) {
            super.add(instruction);
        }
    }

    public final ExtendedInsnList frame(int type, int numLocal, Object[] local, int numStack, Object[] stack) {
        return this.append(new FrameNode(
            type,
            numLocal,
            local == null ? null : getLabelNodes(local),
            numStack,
            stack == null ? null : getLabelNodes(stack)
        ));
    }

    /**
     * @see InsnNode
     */
    public final ExtendedInsnList insn(int opcode) {
        return this.append(new InsnNode(opcode));
    }

    public final ExtendedInsnList nop() {
        return this.append(new InsnNode(Opcodes.NOP));
    }

    public final ExtendedInsnList aconst_null() {
        return this.append(new InsnNode(Opcodes.ACONST_NULL));
    }

    public final ExtendedInsnList iconst_m1() {
        return this.append(new InsnNode(Opcodes.ICONST_M1));
    }

    public final ExtendedInsnList iconst_0() {
        return this.append(new InsnNode(Opcodes.ICONST_0));
    }

    public final ExtendedInsnList iconst_1() {
        return this.append(new InsnNode(Opcodes.ICONST_1));
    }

    public final ExtendedInsnList iconst_2() {
        return this.append(new InsnNode(Opcodes.ICONST_2));
    }

    public final ExtendedInsnList iconst_3() {
        return this.append(new InsnNode(Opcodes.ICONST_3));
    }

    public final ExtendedInsnList iconst_4() {
        return this.append(new InsnNode(Opcodes.ICONST_4));
    }

    public final ExtendedInsnList iconst_5() {
        return this.append(new InsnNode(Opcodes.ICONST_5));
    }

    public final ExtendedInsnList lconst_0() {
        return this.append(new InsnNode(Opcodes.LCONST_0));
    }

    public final ExtendedInsnList lconst_1() {
        return this.append(new InsnNode(Opcodes.LCONST_1));
    }

    public final ExtendedInsnList fconst_0() {
        return this.append(new InsnNode(Opcodes.FCONST_0));
    }

    public final ExtendedInsnList fconst_1() {
        return this.append(new InsnNode(Opcodes.FCONST_1));
    }

    public final ExtendedInsnList fconst_2() {
        return this.append(new InsnNode(Opcodes.FCONST_2));
    }

    public final ExtendedInsnList dconst_0() {
        return this.append(new InsnNode(Opcodes.DCONST_0));
    }

    public final ExtendedInsnList dconst_1() {
        return this.append(new InsnNode(Opcodes.DCONST_1));
    }

    public final ExtendedInsnList iaload() {
        return this.append(new InsnNode(Opcodes.IALOAD));
    }

    public final ExtendedInsnList laload() {
        return this.append(new InsnNode(Opcodes.LALOAD));
    }

    public final ExtendedInsnList faload() {
        return this.append(new InsnNode(Opcodes.FALOAD));
    }

    public final ExtendedInsnList daload() {
        return this.append(new InsnNode(Opcodes.DALOAD));
    }

    public final ExtendedInsnList aaload() {
        return this.append(new InsnNode(Opcodes.AALOAD));
    }

    public final ExtendedInsnList baload() {
        return this.append(new InsnNode(Opcodes.BALOAD));
    }

    public final ExtendedInsnList caload() {
        return this.append(new InsnNode(Opcodes.CALOAD));
    }

    public final ExtendedInsnList saload() {
        return this.append(new InsnNode(Opcodes.SALOAD));
    }

    public final ExtendedInsnList iastore() {
        return this.append(new InsnNode(Opcodes.IASTORE));
    }

    public final ExtendedInsnList lastore() {
        return this.append(new InsnNode(Opcodes.LASTORE));
    }

    public final ExtendedInsnList fastore() {
        return this.append(new InsnNode(Opcodes.FASTORE));
    }

    public final ExtendedInsnList dastore() {
        return this.append(new InsnNode(Opcodes.DASTORE));
    }

    public final ExtendedInsnList aastore() {
        return this.append(new InsnNode(Opcodes.AASTORE));
    }

    public final ExtendedInsnList bastore() {
        return this.append(new InsnNode(Opcodes.BASTORE));
    }

    public final ExtendedInsnList castore() {
        return this.append(new InsnNode(Opcodes.CASTORE));
    }

    public final ExtendedInsnList sastore() {
        return this.append(new InsnNode(Opcodes.SASTORE));
    }

    public final ExtendedInsnList pop() {
        return this.append(new InsnNode(Opcodes.POP));
    }

    public final ExtendedInsnList pop2() {
        return this.append(new InsnNode(Opcodes.POP2));
    }

    public final ExtendedInsnList dup() {
        return this.append(new InsnNode(Opcodes.DUP));
    }

    public final ExtendedInsnList dup_x1() {
        return this.append(new InsnNode(Opcodes.DUP_X1));
    }

    public final ExtendedInsnList dup_x2() {
        return this.append(new InsnNode(Opcodes.DUP_X2));
    }

    public final ExtendedInsnList dup2() {
        return this.append(new InsnNode(Opcodes.DUP2));
    }

    public final ExtendedInsnList dup2_x1() {
        return this.append(new InsnNode(Opcodes.DUP2_X1));
    }

    public final ExtendedInsnList dup2_x2() {
        return this.append(new InsnNode(Opcodes.DUP2_X2));
    }

    public final ExtendedInsnList swap() {
        return this.append(new InsnNode(Opcodes.SWAP));
    }

    public final ExtendedInsnList iadd() {
        return this.append(new InsnNode(Opcodes.IADD));
    }

    public final ExtendedInsnList ladd() {
        return this.append(new InsnNode(Opcodes.LADD));
    }

    public final ExtendedInsnList fadd() {
        return this.append(new InsnNode(Opcodes.FADD));
    }

    public final ExtendedInsnList dadd() {
        return this.append(new InsnNode(Opcodes.DADD));
    }

    public final ExtendedInsnList isub() {
        return this.append(new InsnNode(Opcodes.ISUB));
    }

    public final ExtendedInsnList lsub() {
        return this.append(new InsnNode(Opcodes.LSUB));
    }

    public final ExtendedInsnList fsub() {
        return this.append(new InsnNode(Opcodes.FSUB));
    }

    public final ExtendedInsnList dsub() {
        return this.append(new InsnNode(Opcodes.DSUB));
    }

    public final ExtendedInsnList imul() {
        return this.append(new InsnNode(Opcodes.IMUL));
    }

    public final ExtendedInsnList lmul() {
        return this.append(new InsnNode(Opcodes.LMUL));
    }

    public final ExtendedInsnList fmul() {
        return this.append(new InsnNode(Opcodes.FMUL));
    }

    public final ExtendedInsnList dmul() {
        return this.append(new InsnNode(Opcodes.DMUL));
    }

    public final ExtendedInsnList idiv() {
        return this.append(new InsnNode(Opcodes.IDIV));
    }

    public final ExtendedInsnList ldiv() {
        return this.append(new InsnNode(Opcodes.LDIV));
    }

    public final ExtendedInsnList fdiv() {
        return this.append(new InsnNode(Opcodes.FDIV));
    }

    public final ExtendedInsnList ddiv() {
        return this.append(new InsnNode(Opcodes.DDIV));
    }

    public final ExtendedInsnList irem() {
        return this.append(new InsnNode(Opcodes.IREM));
    }

    public final ExtendedInsnList lrem() {
        return this.append(new InsnNode(Opcodes.LREM));
    }

    public final ExtendedInsnList frem() {
        return this.append(new InsnNode(Opcodes.FREM));
    }

    public final ExtendedInsnList drem() {
        return this.append(new InsnNode(Opcodes.DREM));
    }

    public final ExtendedInsnList ineg() {
        return this.append(new InsnNode(Opcodes.INEG));
    }

    public final ExtendedInsnList lneg() {
        return this.append(new InsnNode(Opcodes.LNEG));
    }

    public final ExtendedInsnList fneg() {
        return this.append(new InsnNode(Opcodes.FNEG));
    }

    public final ExtendedInsnList dneg() {
        return this.append(new InsnNode(Opcodes.DNEG));
    }

    public final ExtendedInsnList ishl() {
        return this.append(new InsnNode(Opcodes.ISHL));
    }

    public final ExtendedInsnList lshl() {
        return this.append(new InsnNode(Opcodes.LSHL));
    }

    public final ExtendedInsnList ishr() {
        return this.append(new InsnNode(Opcodes.ISHR));
    }

    public final ExtendedInsnList lshr() {
        return this.append(new InsnNode(Opcodes.LSHR));
    }

    public final ExtendedInsnList iushr() {
        return this.append(new InsnNode(Opcodes.IUSHR));
    }

    public final ExtendedInsnList lushr() {
        return this.append(new InsnNode(Opcodes.LUSHR));
    }

    public final ExtendedInsnList iand() {
        return this.append(new InsnNode(Opcodes.IAND));
    }

    public final ExtendedInsnList land() {
        return this.append(new InsnNode(Opcodes.LAND));
    }

    public final ExtendedInsnList ior() {
        return this.append(new InsnNode(Opcodes.IOR));
    }

    public final ExtendedInsnList lor() {
        return this.append(new InsnNode(Opcodes.LOR));
    }

    public final ExtendedInsnList ixor() {
        return this.append(new InsnNode(Opcodes.IXOR));
    }

    public final ExtendedInsnList lxor() {
        return this.append(new InsnNode(Opcodes.LXOR));
    }

    public final ExtendedInsnList i2l() {
        return this.append(new InsnNode(Opcodes.I2L));
    }

    public final ExtendedInsnList i2f() {
        return this.append(new InsnNode(Opcodes.I2F));
    }

    public final ExtendedInsnList i2d() {
        return this.append(new InsnNode(Opcodes.I2D));
    }

    public final ExtendedInsnList l2i() {
        return this.append(new InsnNode(Opcodes.L2I));
    }

    public final ExtendedInsnList l2f() {
        return this.append(new InsnNode(Opcodes.L2F));
    }

    public final ExtendedInsnList l2d() {
        return this.append(new InsnNode(Opcodes.L2D));
    }

    public final ExtendedInsnList f2i() {
        return this.append(new InsnNode(Opcodes.F2I));
    }

    public final ExtendedInsnList f2l() {
        return this.append(new InsnNode(Opcodes.F2L));
    }

    public final ExtendedInsnList f2d() {
        return this.append(new InsnNode(Opcodes.F2D));
    }

    public final ExtendedInsnList d2i() {
        return this.append(new InsnNode(Opcodes.D2I));
    }

    public final ExtendedInsnList d2l() {
        return this.append(new InsnNode(Opcodes.D2L));
    }

    public final ExtendedInsnList d2f() {
        return this.append(new InsnNode(Opcodes.D2F));
    }

    public final ExtendedInsnList i2b() {
        return this.append(new InsnNode(Opcodes.I2B));
    }

    public final ExtendedInsnList i2c() {
        return this.append(new InsnNode(Opcodes.I2C));
    }

    public final ExtendedInsnList i2s() {
        return this.append(new InsnNode(Opcodes.I2S));
    }

    public final ExtendedInsnList lcmp() {
        return this.append(new InsnNode(Opcodes.LCMP));
    }

    public final ExtendedInsnList fcmpl() {
        return this.append(new InsnNode(Opcodes.FCMPL));
    }

    public final ExtendedInsnList fcmpg() {
        return this.append(new InsnNode(Opcodes.FCMPG));
    }

    public final ExtendedInsnList dcmpl() {
        return this.append(new InsnNode(Opcodes.DCMPL));
    }

    public final ExtendedInsnList dcmpg() {
        return this.append(new InsnNode(Opcodes.DCMPG));
    }

    public final ExtendedInsnList ireturn() {
        return this.append(new InsnNode(Opcodes.IRETURN));
    }

    public final ExtendedInsnList lreturn() {
        return this.append(new InsnNode(Opcodes.LRETURN));
    }

    public final ExtendedInsnList freturn() {
        return this.append(new InsnNode(Opcodes.FRETURN));
    }

    public final ExtendedInsnList dreturn() {
        return this.append(new InsnNode(Opcodes.DRETURN));
    }

    public final ExtendedInsnList areturn() {
        return this.append(new InsnNode(Opcodes.ARETURN));
    }

    public final ExtendedInsnList vreturn() {
        return this.append(new InsnNode(Opcodes.RETURN));
    }

    public final ExtendedInsnList arraylength() {
        return this.append(new InsnNode(Opcodes.ARRAYLENGTH));
    }

    public final ExtendedInsnList athrow() {
        return this.append(new InsnNode(Opcodes.ATHROW));
    }

    public final ExtendedInsnList monitorenter() {
        return this.append(new InsnNode(Opcodes.MONITORENTER));
    }

    public final ExtendedInsnList monitorexit() {
        return this.append(new InsnNode(Opcodes.MONITOREXIT));
    }

    /**
     * @see IntInsnNode
     */
    public final ExtendedInsnList intInsn(int opcode, int operand) {
        return this.append(new IntInsnNode(opcode, operand));
    }

    public final ExtendedInsnList bipush(int operand) {
        return this.append(new IntInsnNode(Opcodes.BIPUSH, operand));
    }

    public final ExtendedInsnList sipush(int operand) {
        return this.append(new IntInsnNode(Opcodes.SIPUSH, operand));
    }

    public final ExtendedInsnList newarray(int operand) {
        return this.append(new IntInsnNode(Opcodes.NEWARRAY, operand));
    }

    /**
     * @see VarInsnNode
     */
    public final ExtendedInsnList varInsn(int opcode, int var) {
        return this.append(new VarInsnNode(opcode, var));
    }

    public final ExtendedInsnList iload(int var) {
        return this.append(new VarInsnNode(Opcodes.ILOAD, var));
    }

    public final ExtendedInsnList lload(int var) {
        return this.append(new VarInsnNode(Opcodes.LLOAD, var));
    }

    public final ExtendedInsnList fload(int var) {
        return this.append(new VarInsnNode(Opcodes.FLOAD, var));
    }

    public final ExtendedInsnList dload(int var) {
        return this.append(new VarInsnNode(Opcodes.DLOAD, var));
    }

    public final ExtendedInsnList aload(int var) {
        return this.append(new VarInsnNode(Opcodes.ALOAD, var));
    }

    public final ExtendedInsnList istore(int var) {
        return this.append(new VarInsnNode(Opcodes.ISTORE, var));
    }

    public final ExtendedInsnList lstore(int var) {
        return this.append(new VarInsnNode(Opcodes.LSTORE, var));
    }

    public final ExtendedInsnList fstore(int var) {
        return this.append(new VarInsnNode(Opcodes.FSTORE, var));
    }

    public final ExtendedInsnList dstore(int var) {
        return this.append(new VarInsnNode(Opcodes.DSTORE, var));
    }

    public final ExtendedInsnList astore(int var) {
        return this.append(new VarInsnNode(Opcodes.ASTORE, var));
    }

    public final ExtendedInsnList ret(int var) {
        return this.append(new VarInsnNode(Opcodes.RET, var));
    }

    /**
     * @see TypeInsnNode
     */
    public final ExtendedInsnList type(int opcode, String type) {
        return this.append(new TypeInsnNode(opcode, type));
    }

    public final ExtendedInsnList anew(String descriptor) {
        return this.append(new TypeInsnNode(Opcodes.NEW, descriptor));
    }

    public final ExtendedInsnList anewarray(String descriptor) {
        return this.append(new TypeInsnNode(Opcodes.ANEWARRAY, descriptor));
    }

    public final ExtendedInsnList checkcast(String descriptor) {
        return this.append(new TypeInsnNode(Opcodes.CHECKCAST, descriptor));
    }

    public final ExtendedInsnList instance(String descriptor) {
        return this.append(new TypeInsnNode(Opcodes.INSTANCEOF, descriptor));
    }

    /**
     * @see FieldInsnNode
     */
    public final ExtendedInsnList field(int opcode, String owner, String name, String descriptor) {
        return this.append(new FieldInsnNode(opcode, owner, name, descriptor));
    }

    public final ExtendedInsnList getstatic(String owner, String name, String descriptor) {
        return this.append(new FieldInsnNode(Opcodes.GETSTATIC, owner, name, descriptor));
    }

    public final ExtendedInsnList putstatic(String owner, String name, String descriptor) {
        return this.append(new FieldInsnNode(Opcodes.PUTSTATIC, owner, name, descriptor));
    }

    public final ExtendedInsnList getfield(String owner, String name, String descriptor) {
        return this.append(new FieldInsnNode(Opcodes.GETFIELD, owner, name, descriptor));
    }

    public final ExtendedInsnList putfield(String owner, String name, String descriptor) {
        return this.append(new FieldInsnNode(Opcodes.PUTFIELD, owner, name, descriptor));
    }

    /**
     * @see MethodInsnNode
     */
    public final ExtendedInsnList method(int opcode, String owner, String name, String descriptor, boolean isInterface) {
        return this.append(new MethodInsnNode(opcode, owner, name, descriptor, isInterface));
    }

    public final ExtendedInsnList invokevirtual(String owner, String name, String descriptor) {
        return this.append(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, owner, name, descriptor, false));
    }

    public final ExtendedInsnList invokespecial(String owner, String name, String descriptor) {
        return this.append(new MethodInsnNode(Opcodes.INVOKESPECIAL, owner, name, descriptor, false));
    }

    public final ExtendedInsnList invokestatic(String owner, String name, String descriptor, boolean isInterface) {
        return this.append(new MethodInsnNode(Opcodes.INVOKESTATIC, owner, name, descriptor, isInterface));
    }

    public final ExtendedInsnList invokeinterface(String owner, String name, String descriptor) {
        return this.append(new MethodInsnNode(Opcodes.INVOKEINTERFACE, owner, name, descriptor, true));
    }

    /**
     * @see InvokeDynamicInsnNode
     */
    public final ExtendedInsnList invokedynamic(String name, String descriptor, Handle bootstrapMethodHandle, Object... bootstrapMethodArguments) {
        return this.append(new InvokeDynamicInsnNode(name, descriptor, bootstrapMethodHandle, bootstrapMethodArguments));
    }

    /**
     * @see JumpInsnNode
     */
    public final ExtendedInsnList jump(int opcode, String label) {
        return this.append(new JumpInsnNode(opcode, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList jump(int opcode, Label label) {
        return this.append(new JumpInsnNode(opcode, getLabelNode(label)));
    }

    public final ExtendedInsnList jump(int opcode, LabelNode label) {
        return this.append(new JumpInsnNode(opcode, label));
    }

    public final ExtendedInsnList ifeq(String label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList ifeq(Label label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, getLabelNode(label)));
    }

    public final ExtendedInsnList ifeq(LabelNode label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, label));
    }

    public final ExtendedInsnList ifne(String label) {
        return this.append(new JumpInsnNode(Opcodes.IFNE, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList ifne(Label label) {
        return this.append(new JumpInsnNode(Opcodes.IFNE, getLabelNode(label)));
    }

    public final ExtendedInsnList ifne(LabelNode label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, label));
    }

    public final ExtendedInsnList iflt(String label) {
        return this.append(new JumpInsnNode(Opcodes.IFLT, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList iflt(Label label) {
        return this.append(new JumpInsnNode(Opcodes.IFLT, getLabelNode(label)));
    }

    public final ExtendedInsnList iflt(LabelNode label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, label));
    }

    public final ExtendedInsnList ifge(String label) {
        return this.append(new JumpInsnNode(Opcodes.IFGE, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList ifge(Label label) {
        return this.append(new JumpInsnNode(Opcodes.IFGE, getLabelNode(label)));
    }

    public final ExtendedInsnList ifge(LabelNode label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, label));
    }

    public final ExtendedInsnList ifgt(String label) {
        return this.append(new JumpInsnNode(Opcodes.IFGT, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList ifgt(Label label) {
        return this.append(new JumpInsnNode(Opcodes.IFGT, getLabelNode(label)));
    }

    public final ExtendedInsnList ifgt(LabelNode label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, label));
    }

    public final ExtendedInsnList ifle(String label) {
        return this.append(new JumpInsnNode(Opcodes.IFLE, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList ifle(Label label) {
        return this.append(new JumpInsnNode(Opcodes.IFLE, getLabelNode(label)));
    }

    public final ExtendedInsnList ifle(LabelNode label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, label));
    }

    public final ExtendedInsnList if_icmpeq(String label) {
        return this.append(new JumpInsnNode(Opcodes.IF_ICMPEQ, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList if_icmpeq(Label label) {
        return this.append(new JumpInsnNode(Opcodes.IF_ICMPEQ, getLabelNode(label)));
    }

    public final ExtendedInsnList if_icmpeq(LabelNode label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, label));
    }

    public final ExtendedInsnList if_icmpne(String label) {
        return this.append(new JumpInsnNode(Opcodes.IF_ICMPNE, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList if_icmpne(Label label) {
        return this.append(new JumpInsnNode(Opcodes.IF_ICMPNE, getLabelNode(label)));
    }

    public final ExtendedInsnList if_icmpne(LabelNode label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, label));
    }

    public final ExtendedInsnList if_icmplt(String label) {
        return this.append(new JumpInsnNode(Opcodes.IF_ICMPLT, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList if_icmplt(Label label) {
        return this.append(new JumpInsnNode(Opcodes.IF_ICMPLT, getLabelNode(label)));
    }

    public final ExtendedInsnList if_icmplt(LabelNode label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, label));
    }

    public final ExtendedInsnList if_icmpge(String label) {
        return this.append(new JumpInsnNode(Opcodes.IF_ICMPGE, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList if_icmpge(Label label) {
        return this.append(new JumpInsnNode(Opcodes.IF_ICMPGE, getLabelNode(label)));
    }

    public final ExtendedInsnList if_icmpge(LabelNode label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, label));
    }

    public final ExtendedInsnList if_icmpgt(String label) {
        return this.append(new JumpInsnNode(Opcodes.IF_ICMPGT, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList if_icmpgt(Label label) {
        return this.append(new JumpInsnNode(Opcodes.IF_ICMPGT, getLabelNode(label)));
    }

    public final ExtendedInsnList if_icmpgt(LabelNode label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, label));
    }

    public final ExtendedInsnList if_icmple(String label) {
        return this.append(new JumpInsnNode(Opcodes.IF_ICMPLE, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList if_icmple(Label label) {
        return this.append(new JumpInsnNode(Opcodes.IF_ICMPLE, getLabelNode(label)));
    }

    public final ExtendedInsnList if_icmple(LabelNode label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, label));
    }

    public final ExtendedInsnList if_acmpeq(String label) {
        return this.append(new JumpInsnNode(Opcodes.IF_ACMPEQ, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList if_acmpeq(Label label) {
        return this.append(new JumpInsnNode(Opcodes.IF_ACMPEQ, getLabelNode(label)));
    }

    public final ExtendedInsnList if_acmpeq(LabelNode label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, label));
    }

    public final ExtendedInsnList if_acmpne(String label) {
        return this.append(new JumpInsnNode(Opcodes.IF_ACMPNE, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList if_acmpne(Label label) {
        return this.append(new JumpInsnNode(Opcodes.IF_ACMPNE, getLabelNode(label)));
    }

    public final ExtendedInsnList if_acmpne(LabelNode label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, label));
    }

    public final ExtendedInsnList go_to(String label) {
        return this.append(new JumpInsnNode(Opcodes.GOTO, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList go_to(Label label) {
        return this.append(new JumpInsnNode(Opcodes.GOTO, getLabelNode(label)));
    }

    public final ExtendedInsnList go_to(LabelNode label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, label));
    }

    public final ExtendedInsnList jsr(String label) {
        return this.append(new JumpInsnNode(Opcodes.JSR, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList jsr(Label label) {
        return this.append(new JumpInsnNode(Opcodes.JSR, getLabelNode(label)));
    }

    public final ExtendedInsnList jsr(LabelNode label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, label));
    }

    public final ExtendedInsnList ifnull(String label) {
        return this.append(new JumpInsnNode(Opcodes.IFNULL, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList ifnull (Label label) {
        return this.append(new JumpInsnNode(Opcodes.IFNULL, getLabelNode(label)));
    }

    public final ExtendedInsnList ifnull(LabelNode label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, label));
    }

    public final ExtendedInsnList ifnonnull(String label) {
        return this.append(new JumpInsnNode(Opcodes.IFNONNULL, getLabelNode(this.labels.computeIfAbsent(label, labelConstructor))));
    }

    public final ExtendedInsnList ifnonnull(Label label) {
        return this.append(new JumpInsnNode(Opcodes.IFNONNULL, getLabelNode(label)));
    }

    public final ExtendedInsnList ifnonnull(LabelNode label) {
        return this.append(new JumpInsnNode(Opcodes.IFEQ, label));
    }

    public final ExtendedInsnList label(String label) {
        return this.append(getLabelNode(this.labels.computeIfAbsent(label, labelConstructor)));
    }

    public final ExtendedInsnList label(Label label) {
        return this.append(getLabelNode(label));
    }

    public final ExtendedInsnList ldc(Object value) {
        return this.append(new LdcInsnNode(value));
    }

    public final ExtendedInsnList iinc(int var, int increment) {
        return this.append(new IincInsnNode(var, increment));
    }

    public final ExtendedInsnList tableswitch(int min, int max, Label dflt, Label... labels) {
        return this.append(new TableSwitchInsnNode(min, max, getLabelNode(dflt), getLabelNodes(labels)));
    }

    public final ExtendedInsnList lookupswitch(Label dflt, int[] keys, Label[] labels) {
        return this.append(new LookupSwitchInsnNode(getLabelNode(dflt), keys, getLabelNodes(labels)));
    }

    public final ExtendedInsnList multianewarray(String descriptor, int numDimensions) {
        return this.append(new MultiANewArrayInsnNode(descriptor, numDimensions));
    }
}