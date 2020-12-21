package user11681.shortcode.instruction;

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
    public ExtendedInsnList() {}

    public ExtendedInsnList(AbstractInsnNode... instructions) {
        this.add(instructions);
    }

    public ExtendedInsnList(InsnList instructions) {
        super.add(instructions);
    }

    private static Object[] getLabelNodes(final Object[] objects) {
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

    private static LabelNode[] getLabelNodes(final Label[] labels) {
        final LabelNode[] labelNodes = new LabelNode[labels.length];

        for (int i = 0, n = labels.length; i < n; ++i) {
            labelNodes[i] = getLabelNode(labels[i]);
        }

        return labelNodes;
    }

    private static LabelNode getLabelNode(final Label label) {
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

    public final ExtendedInsnList frame(final int type, final int numLocal, final Object[] local, final int numStack, final Object[] stack) {
        super.add(new FrameNode(
            type,
            numLocal,
            local == null ? null : getLabelNodes(local),
            numStack,
            stack == null ? null : getLabelNodes(stack)
        ));

        return this;
    }

    /**
     * @see InsnNode
     */
    public final ExtendedInsnList insn(final int opcode) {
        super.add(new InsnNode(opcode));

        return this;
    }

    public final ExtendedInsnList nop() {
        super.add(new InsnNode(Opcodes.NOP));

        return this;
    }

    public final ExtendedInsnList aconst_null() {
        super.add(new InsnNode(Opcodes.ACONST_NULL));

        return this;
    }

    public final ExtendedInsnList iconst_m1() {
        super.add(new InsnNode(Opcodes.ICONST_M1));

        return this;
    }

    public final ExtendedInsnList iconst_0() {
        super.add(new InsnNode(Opcodes.ICONST_0));

        return this;
    }

    public final ExtendedInsnList iconst_1() {
        super.add(new InsnNode(Opcodes.ICONST_1));

        return this;
    }

    public final ExtendedInsnList iconst_2() {
        super.add(new InsnNode(Opcodes.ICONST_2));

        return this;
    }

    public final ExtendedInsnList iconst_3() {
        super.add(new InsnNode(Opcodes.ICONST_3));

        return this;
    }

    public final ExtendedInsnList iconst_4() {
        super.add(new InsnNode(Opcodes.ICONST_4));

        return this;
    }

    public final ExtendedInsnList iconst_5() {
        super.add(new InsnNode(Opcodes.ICONST_5));

        return this;
    }

    public final ExtendedInsnList lconst_0() {
        super.add(new InsnNode(Opcodes.LCONST_0));

        return this;
    }

    public final ExtendedInsnList lconst_1() {
        super.add(new InsnNode(Opcodes.LCONST_1));

        return this;
    }

    public final ExtendedInsnList fconst_0() {
        super.add(new InsnNode(Opcodes.FCONST_0));

        return this;
    }

    public final ExtendedInsnList fconst_1() {
        super.add(new InsnNode(Opcodes.FCONST_1));

        return this;
    }

    public final ExtendedInsnList fconst_2() {
        super.add(new InsnNode(Opcodes.FCONST_2));

        return this;
    }

    public final ExtendedInsnList dconst_0() {
        super.add(new InsnNode(Opcodes.DCONST_0));

        return this;
    }

    public final ExtendedInsnList dconst_1() {
        super.add(new InsnNode(Opcodes.DCONST_1));

        return this;
    }

    public final ExtendedInsnList iaload() {
        super.add(new InsnNode(Opcodes.IALOAD));

        return this;
    }

    public final ExtendedInsnList laload() {
        super.add(new InsnNode(Opcodes.LALOAD));

        return this;
    }

    public final ExtendedInsnList faload() {
        super.add(new InsnNode(Opcodes.FALOAD));

        return this;
    }

    public final ExtendedInsnList daload() {
        super.add(new InsnNode(Opcodes.DALOAD));

        return this;
    }

    public final ExtendedInsnList aaload() {
        super.add(new InsnNode(Opcodes.AALOAD));

        return this;
    }

    public final ExtendedInsnList baload() {
        super.add(new InsnNode(Opcodes.BALOAD));

        return this;
    }

    public final ExtendedInsnList caload() {
        super.add(new InsnNode(Opcodes.CALOAD));

        return this;
    }

    public final ExtendedInsnList saload() {
        super.add(new InsnNode(Opcodes.SALOAD));

        return this;
    }

    public final ExtendedInsnList iastore() {
        super.add(new InsnNode(Opcodes.IASTORE));

        return this;
    }

    public final ExtendedInsnList lastore() {
        super.add(new InsnNode(Opcodes.LASTORE));

        return this;
    }

    public final ExtendedInsnList fastore() {
        super.add(new InsnNode(Opcodes.FASTORE));

        return this;
    }

    public final ExtendedInsnList dastore() {
        super.add(new InsnNode(Opcodes.DASTORE));

        return this;
    }

    public final ExtendedInsnList aastore() {
        super.add(new InsnNode(Opcodes.AASTORE));

        return this;
    }

    public final ExtendedInsnList bastore() {
        super.add(new InsnNode(Opcodes.BASTORE));

        return this;
    }

    public final ExtendedInsnList castore() {
        super.add(new InsnNode(Opcodes.CASTORE));

        return this;
    }

    public final ExtendedInsnList sastore() {
        super.add(new InsnNode(Opcodes.SASTORE));

        return this;
    }

    public final ExtendedInsnList pop() {
        super.add(new InsnNode(Opcodes.POP));

        return this;
    }

    public final ExtendedInsnList pop2() {
        super.add(new InsnNode(Opcodes.POP2));

        return this;
    }

    public final ExtendedInsnList dup() {
        super.add(new InsnNode(Opcodes.DUP));

        return this;
    }

    public final ExtendedInsnList dup_x1() {
        super.add(new InsnNode(Opcodes.DUP_X1));

        return this;
    }

    public final ExtendedInsnList dup_x2() {
        super.add(new InsnNode(Opcodes.DUP_X2));

        return this;
    }

    public final ExtendedInsnList dup2() {
        super.add(new InsnNode(Opcodes.DUP2));

        return this;
    }

    public final ExtendedInsnList dup2_x1() {
        super.add(new InsnNode(Opcodes.DUP2_X1));

        return this;
    }

    public final ExtendedInsnList dup2_x2() {
        super.add(new InsnNode(Opcodes.DUP2_X2));

        return this;
    }

    public final ExtendedInsnList swap() {
        super.add(new InsnNode(Opcodes.SWAP));

        return this;
    }

    public final ExtendedInsnList iadd() {
        super.add(new InsnNode(Opcodes.IADD));

        return this;
    }

    public final ExtendedInsnList ladd() {
        super.add(new InsnNode(Opcodes.LADD));

        return this;
    }

    public final ExtendedInsnList fadd() {
        super.add(new InsnNode(Opcodes.FADD));

        return this;
    }

    public final ExtendedInsnList dadd() {
        super.add(new InsnNode(Opcodes.DADD));

        return this;
    }

    public final ExtendedInsnList isub() {
        super.add(new InsnNode(Opcodes.ISUB));

        return this;
    }

    public final ExtendedInsnList lsub() {
        super.add(new InsnNode(Opcodes.LSUB));

        return this;
    }

    public final ExtendedInsnList fsub() {
        super.add(new InsnNode(Opcodes.FSUB));

        return this;
    }

    public final ExtendedInsnList dsub() {
        super.add(new InsnNode(Opcodes.DSUB));

        return this;
    }

    public final ExtendedInsnList imul() {
        super.add(new InsnNode(Opcodes.IMUL));

        return this;
    }

    public final ExtendedInsnList lmul() {
        super.add(new InsnNode(Opcodes.LMUL));

        return this;
    }

    public final ExtendedInsnList fmul() {
        super.add(new InsnNode(Opcodes.FMUL));

        return this;
    }

    public final ExtendedInsnList dmul() {
        super.add(new InsnNode(Opcodes.DMUL));

        return this;
    }

    public final ExtendedInsnList idiv() {
        super.add(new InsnNode(Opcodes.IDIV));

        return this;
    }

    public final ExtendedInsnList ldiv() {
        super.add(new InsnNode(Opcodes.LDIV));

        return this;
    }

    public final ExtendedInsnList fdiv() {
        super.add(new InsnNode(Opcodes.FDIV));

        return this;
    }

    public final ExtendedInsnList ddiv() {
        super.add(new InsnNode(Opcodes.DDIV));

        return this;
    }

    public final ExtendedInsnList irem() {
        super.add(new InsnNode(Opcodes.IREM));

        return this;
    }

    public final ExtendedInsnList lrem() {
        super.add(new InsnNode(Opcodes.LREM));

        return this;
    }

    public final ExtendedInsnList frem() {
        super.add(new InsnNode(Opcodes.FREM));

        return this;
    }

    public final ExtendedInsnList drem() {
        super.add(new InsnNode(Opcodes.DREM));

        return this;
    }

    public final ExtendedInsnList ineg() {
        super.add(new InsnNode(Opcodes.INEG));

        return this;
    }

    public final ExtendedInsnList lneg() {
        super.add(new InsnNode(Opcodes.LNEG));

        return this;
    }

    public final ExtendedInsnList fneg() {
        super.add(new InsnNode(Opcodes.FNEG));

        return this;
    }

    public final ExtendedInsnList dneg() {
        super.add(new InsnNode(Opcodes.DNEG));

        return this;
    }

    public final ExtendedInsnList ishl() {
        super.add(new InsnNode(Opcodes.ISHL));

        return this;
    }

    public final ExtendedInsnList lshl() {
        super.add(new InsnNode(Opcodes.LSHL));

        return this;
    }

    public final ExtendedInsnList ishr() {
        super.add(new InsnNode(Opcodes.ISHR));

        return this;
    }

    public final ExtendedInsnList lshr() {
        super.add(new InsnNode(Opcodes.LSHR));

        return this;
    }

    public final ExtendedInsnList iushr() {
        super.add(new InsnNode(Opcodes.IUSHR));

        return this;
    }

    public final ExtendedInsnList lushr() {
        super.add(new InsnNode(Opcodes.LUSHR));

        return this;
    }

    public final ExtendedInsnList iand() {
        super.add(new InsnNode(Opcodes.IAND));

        return this;
    }

    public final ExtendedInsnList land() {
        super.add(new InsnNode(Opcodes.LAND));

        return this;
    }

    public final ExtendedInsnList ior() {
        super.add(new InsnNode(Opcodes.IOR));

        return this;
    }

    public final ExtendedInsnList lor() {
        super.add(new InsnNode(Opcodes.LOR));

        return this;
    }

    public final ExtendedInsnList ixor() {
        super.add(new InsnNode(Opcodes.IXOR));

        return this;
    }

    public final ExtendedInsnList lxor() {
        super.add(new InsnNode(Opcodes.LXOR));

        return this;
    }

    public final ExtendedInsnList i2l() {
        super.add(new InsnNode(Opcodes.I2L));

        return this;
    }

    public final ExtendedInsnList i2f() {
        super.add(new InsnNode(Opcodes.I2F));

        return this;
    }

    public final ExtendedInsnList i2d() {
        super.add(new InsnNode(Opcodes.I2D));

        return this;
    }

    public final ExtendedInsnList l2i() {
        super.add(new InsnNode(Opcodes.L2I));

        return this;
    }

    public final ExtendedInsnList l2f() {
        super.add(new InsnNode(Opcodes.L2F));

        return this;
    }

    public final ExtendedInsnList l2d() {
        super.add(new InsnNode(Opcodes.L2D));

        return this;
    }

    public final ExtendedInsnList f2i() {
        super.add(new InsnNode(Opcodes.F2I));

        return this;
    }

    public final ExtendedInsnList f2l() {
        super.add(new InsnNode(Opcodes.F2L));

        return this;
    }

    public final ExtendedInsnList f2d() {
        super.add(new InsnNode(Opcodes.F2D));

        return this;
    }

    public final ExtendedInsnList d2i() {
        super.add(new InsnNode(Opcodes.D2I));

        return this;
    }

    public final ExtendedInsnList d2l() {
        super.add(new InsnNode(Opcodes.D2L));

        return this;
    }

    public final ExtendedInsnList d2f() {
        super.add(new InsnNode(Opcodes.D2F));

        return this;
    }

    public final ExtendedInsnList i2b() {
        super.add(new InsnNode(Opcodes.I2B));

        return this;
    }

    public final ExtendedInsnList i2c() {
        super.add(new InsnNode(Opcodes.I2C));

        return this;
    }

    public final ExtendedInsnList i2s() {
        super.add(new InsnNode(Opcodes.I2S));

        return this;
    }

    public final ExtendedInsnList lcmp() {
        super.add(new InsnNode(Opcodes.LCMP));

        return this;
    }

    public final ExtendedInsnList fcmpl() {
        super.add(new InsnNode(Opcodes.FCMPL));

        return this;
    }

    public final ExtendedInsnList fcmpg() {
        super.add(new InsnNode(Opcodes.FCMPG));

        return this;
    }

    public final ExtendedInsnList dcmpl() {
        super.add(new InsnNode(Opcodes.DCMPL));

        return this;
    }

    public final ExtendedInsnList dcmpg() {
        super.add(new InsnNode(Opcodes.DCMPG));

        return this;
    }

    public final ExtendedInsnList ireturn() {
        super.add(new InsnNode(Opcodes.IRETURN));

        return this;
    }

    public final ExtendedInsnList lreturn() {
        super.add(new InsnNode(Opcodes.LRETURN));

        return this;
    }

    public final ExtendedInsnList freturn() {
        super.add(new InsnNode(Opcodes.FRETURN));

        return this;
    }

    public final ExtendedInsnList dreturn() {
        super.add(new InsnNode(Opcodes.DRETURN));

        return this;
    }

    public final ExtendedInsnList areturn() {
        super.add(new InsnNode(Opcodes.ARETURN));

        return this;
    }

    public final ExtendedInsnList vreturn() {
        super.add(new InsnNode(Opcodes.RETURN));

        return this;
    }

    public final ExtendedInsnList arraylength() {
        super.add(new InsnNode(Opcodes.ARRAYLENGTH));

        return this;
    }

    public final ExtendedInsnList athrow() {
        super.add(new InsnNode(Opcodes.ATHROW));

        return this;
    }

    public final ExtendedInsnList monitorenter() {
        super.add(new InsnNode(Opcodes.MONITORENTER));

        return this;
    }

    public final ExtendedInsnList monitorexit() {
        super.add(new InsnNode(Opcodes.MONITOREXIT));

        return this;
    }

    /**
     * @see IntInsnNode
     */
    public final ExtendedInsnList intInsn(final int opcode, final int operand) {
        super.add(new IntInsnNode(opcode, operand));

        return this;
    }

    public final ExtendedInsnList bipush(int operand) {
        super.add(new IntInsnNode(Opcodes.BIPUSH, operand));

        return this;
    }

    public final ExtendedInsnList sipush(int operand) {
        super.add(new IntInsnNode(Opcodes.SIPUSH, operand));

        return this;
    }

    public final ExtendedInsnList newarray(int operand) {
        super.add(new IntInsnNode(Opcodes.NEWARRAY, operand));

        return this;
    }

    /**
     * @see VarInsnNode
     */
    public final ExtendedInsnList varInsn(final int opcode, final int var) {
        super.add(new VarInsnNode(opcode, var));

        return this;
    }

    public final ExtendedInsnList iload(int var) {
        super.add(new VarInsnNode(Opcodes.ILOAD, var));

        return this;
    }

    public final ExtendedInsnList lload(int var) {
        super.add(new VarInsnNode(Opcodes.LLOAD, var));

        return this;
    }

    public final ExtendedInsnList fload(int var) {
        super.add(new VarInsnNode(Opcodes.FLOAD, var));

        return this;
    }

    public final ExtendedInsnList dload(int var) {
        super.add(new VarInsnNode(Opcodes.DLOAD, var));

        return this;
    }

    public final ExtendedInsnList aload(int var) {
        super.add(new VarInsnNode(Opcodes.ALOAD, var));

        return this;
    }

    public final ExtendedInsnList istore(int var) {
        super.add(new VarInsnNode(Opcodes.ISTORE, var));

        return this;
    }

    public final ExtendedInsnList lstore(int var) {
        super.add(new VarInsnNode(Opcodes.LSTORE, var));

        return this;
    }

    public final ExtendedInsnList fstore(int var) {
        super.add(new VarInsnNode(Opcodes.FSTORE, var));

        return this;
    }

    public final ExtendedInsnList dstore(int var) {
        super.add(new VarInsnNode(Opcodes.DSTORE, var));

        return this;
    }

    public final ExtendedInsnList astore(int var) {
        super.add(new VarInsnNode(Opcodes.ASTORE, var));

        return this;
    }

    public final ExtendedInsnList ret(int var) {
        super.add(new VarInsnNode(Opcodes.RET, var));

        return this;
    }

    /**
     * @see TypeInsnNode
     */
    public final ExtendedInsnList type(final int opcode, final String type) {
        super.add(new TypeInsnNode(opcode, type));

        return this;
    }

    public final ExtendedInsnList anew(String descriptor) {
        super.add(new TypeInsnNode(Opcodes.NEW, descriptor));

        return this;
    }

    public final ExtendedInsnList anewarray(String descriptor) {
        super.add(new TypeInsnNode(Opcodes.ANEWARRAY, descriptor));

        return this;
    }

    public final ExtendedInsnList checkcast(String descriptor) {
        super.add(new TypeInsnNode(Opcodes.CHECKCAST, descriptor));

        return this;
    }

    public final ExtendedInsnList instance(String descriptor) {
        super.add(new TypeInsnNode(Opcodes.INSTANCEOF, descriptor));

        return this;
    }

    /**
     * @see FieldInsnNode
     */
    public final ExtendedInsnList field(final int opcode, final String owner, final String name, final String descriptor) {
        super.add(new FieldInsnNode(opcode, owner, name, descriptor));

        return this;
    }

    public final ExtendedInsnList getstatic(String owner, String name, String descriptor) {
        super.add(new FieldInsnNode(Opcodes.GETSTATIC, owner, name, descriptor));

        return this;
    }

    public final ExtendedInsnList putstatic(String owner, String name, String descriptor) {
        super.add(new FieldInsnNode(Opcodes.PUTSTATIC, owner, name, descriptor));

        return this;
    }

    public final ExtendedInsnList getfield(String owner, String name, String descriptor) {
        super.add(new FieldInsnNode(Opcodes.GETFIELD, owner, name, descriptor));

        return this;
    }

    public final ExtendedInsnList putfield(String owner, String name, String descriptor) {
        super.add(new FieldInsnNode(Opcodes.PUTFIELD, owner, name, descriptor));

        return this;
    }

    /**
     * @see MethodInsnNode
     */
    public final ExtendedInsnList method(final int opcode, final String owner, final String name, final String descriptor, final boolean isInterface) {
        super.add(new MethodInsnNode(opcode, owner, name, descriptor, isInterface));

        return this;
    }

    public final ExtendedInsnList invokevirtual(String owner, String name, String descriptor) {
        super.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, owner, name, descriptor, false));

        return this;
    }

    public final ExtendedInsnList invokespecial(String owner, String name, String descriptor) {
        super.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, owner, name, descriptor, false));

        return this;
    }

    public final ExtendedInsnList invokestatic(String owner, String name, String descriptor) {
        super.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner, name, descriptor, false));

        return this;
    }

    public final ExtendedInsnList invokeinterface(String owner, String name, String descriptor) {
        super.add(new MethodInsnNode(Opcodes.INVOKEINTERFACE, owner, name, descriptor, true));

        return this;
    }

    /**
     * @see InvokeDynamicInsnNode
     */
    public final ExtendedInsnList invokedynamic(final String name, final String descriptor, final Handle bootstrapMethodHandle, final Object... bootstrapMethodArguments) {
        super.add(new InvokeDynamicInsnNode(name, descriptor, bootstrapMethodHandle, bootstrapMethodArguments));

        return this;
    }

    /**
     * @see JumpInsnNode
     */
    public final ExtendedInsnList jump(final int opcode, final Label label) {
        super.add(new JumpInsnNode(opcode, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList ifeq(Label label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList ifeq(LabelNode label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, label));

        return this;
    }

    public final ExtendedInsnList ifne(Label label) {
        super.add(new JumpInsnNode(Opcodes.IFNE, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList ifne(LabelNode label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, label));

        return this;
    }

    public final ExtendedInsnList iflt(Label label) {
        super.add(new JumpInsnNode(Opcodes.IFLT, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList iflt(LabelNode label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, label));

        return this;
    }

    public final ExtendedInsnList ifge(Label label) {
        super.add(new JumpInsnNode(Opcodes.IFGE, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList ifge(LabelNode label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, label));

        return this;
    }

    public final ExtendedInsnList ifgt(Label label) {
        super.add(new JumpInsnNode(Opcodes.IFGT, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList ifgt(LabelNode label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, label));

        return this;
    }

    public final ExtendedInsnList ifle(Label label) {
        super.add(new JumpInsnNode(Opcodes.IFLE, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList ifle(LabelNode label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, label));

        return this;
    }

    public final ExtendedInsnList if_icmpeq(Label label) {
        super.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList if_icmpeq(LabelNode label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, label));

        return this;
    }

    public final ExtendedInsnList if_icmpne(Label label) {
        super.add(new JumpInsnNode(Opcodes.IF_ICMPNE, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList if_icmpne(LabelNode label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, label));

        return this;
    }

    public final ExtendedInsnList if_icmplt(Label label) {
        super.add(new JumpInsnNode(Opcodes.IF_ICMPLT, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList if_icmplt(LabelNode label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, label));

        return this;
    }

    public final ExtendedInsnList if_icmpge(Label label) {
        super.add(new JumpInsnNode(Opcodes.IF_ICMPGE, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList if_icmpge(LabelNode label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, label));

        return this;
    }

    public final ExtendedInsnList if_icmpgt(Label label) {
        super.add(new JumpInsnNode(Opcodes.IF_ICMPGT, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList if_icmpgt(LabelNode label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, label));

        return this;
    }

    public final ExtendedInsnList if_icmple(Label label) {
        super.add(new JumpInsnNode(Opcodes.IF_ICMPLE, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList if_icmple(LabelNode label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, label));

        return this;
    }

    public final ExtendedInsnList if_acmpeq(Label label) {
        super.add(new JumpInsnNode(Opcodes.IF_ACMPEQ, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList if_acmpeq(LabelNode label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, label));

        return this;
    }

    public final ExtendedInsnList if_acmpne(Label label) {
        super.add(new JumpInsnNode(Opcodes.IF_ACMPNE, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList if_acmpne(LabelNode label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, label));

        return this;
    }

    public final ExtendedInsnList go_to(Label label) {
        super.add(new JumpInsnNode(Opcodes.GOTO, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList go_to(LabelNode label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, label));

        return this;
    }

    public final ExtendedInsnList jsr(Label label) {
        super.add(new JumpInsnNode(Opcodes.JSR, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList jsr(LabelNode label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, label));

        return this;
    }

    public final ExtendedInsnList ifnull (Label label) {
        super.add(new JumpInsnNode(Opcodes.IFNULL, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList ifnull(LabelNode label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, label));

        return this;
    }

    public final ExtendedInsnList ifnonnull(Label label) {
        super.add(new JumpInsnNode(Opcodes.IFNONNULL, getLabelNode(label)));

        return this;
    }

    public final ExtendedInsnList ifnonnull(LabelNode label) {
        super.add(new JumpInsnNode(Opcodes.IFEQ, label));

        return this;
    }

    public final ExtendedInsnList label() {
        super.add(new LabelNode());

        return this;
    }

    public final ExtendedInsnList label(final Label label) {
        super.add(getLabelNode(label));

        return this;
    }

    public final ExtendedInsnList ldc(final Object value) {
        super.add(new LdcInsnNode(value));

        return this;
    }

    public final ExtendedInsnList iinc(final int var, final int increment) {
        super.add(new IincInsnNode(var, increment));

        return this;
    }

    public final ExtendedInsnList tableswitch(final int min, final int max, final Label dflt, final Label... labels) {
        super.add(new TableSwitchInsnNode(min, max, getLabelNode(dflt), getLabelNodes(labels)));

        return this;
    }

    public final ExtendedInsnList lookupswitch(final Label dflt, final int[] keys, final Label[] labels) {
        super.add(new LookupSwitchInsnNode(getLabelNode(dflt), keys, getLabelNodes(labels)));

        return this;
    }

    public final ExtendedInsnList multianewarray(final String descriptor, final int numDimensions) {
        super.add(new MultiANewArrayInsnNode(descriptor, numDimensions));

        return this;
    }
}