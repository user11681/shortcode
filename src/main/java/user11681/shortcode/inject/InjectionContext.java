package user11681.shortcode.inject;

import it.unimi.dsi.fastutil.objects.ReferenceArrayList;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;

public abstract class InjectionContext {
//    public static final InjectionPoint END =
    public final InjectionOffset offset;

    public InjectionContext(final InjectionOffset offset) {
        this.offset = offset;
    }

    public ReferenceArrayList<AbstractInsnNode> findMatches(final InsnList instructions) {
        final ReferenceArrayList<AbstractInsnNode> matches = ReferenceArrayList.wrap(new AbstractInsnNode[3]);

        AbstractInsnNode instruction = instructions.getFirst();

        while (instruction != null) {
            if (this.isMatch(instruction)) {
                matches.add(instruction);
            }

            instruction = instruction.getNext();
        }

        return matches;
    }

    public abstract boolean isMatch(final AbstractInsnNode instruction);
}
