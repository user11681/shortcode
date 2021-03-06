package user11681.shortcode.inject;

import java.util.ArrayList;
import java.util.List;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;

public abstract class InjectionContext {
//    public static final InjectionPoint END =
    public final InjectionOffset offset;

    public InjectionContext(InjectionOffset offset) {
        this.offset = offset;
    }

    public List<AbstractInsnNode> findMatches(final InsnList instructions) {
        List<AbstractInsnNode> matches = new ArrayList<>();

        AbstractInsnNode instruction = instructions.getFirst();

        while (instruction != null) {
            if (this.isMatch(instruction)) {
                matches.add(instruction);
            }

            instruction = instruction.getNext();
        }

        return matches;
    }

    public abstract boolean isMatch(AbstractInsnNode instruction);
}
