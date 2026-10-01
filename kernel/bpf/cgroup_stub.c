/*
 * Minimal BPF_PROG_ATTACH/BPF_PROG_DETACH plumbing.
 *
 * netd attaches its cgroup programs to its cgroup directory at startup and
 * fails when the attach syscall is missing. Resolve the target fd to a
 * cgroup (only cgroup directory fds are supported) and store/clear the
 * program in the cgroup's bpf_stub_progs[] slot.
 *
 * There is no run path: no packet-path hooks, no effective-program
 * computation and no multi-program lists on 3.18 (modelled on 4.9
 * kernel/bpf/cgroup.c). Attached programs are never executed, so
 * BPF_F_ALLOW_MULTI is a simple replace and other attach flags are ignored.
 */

#include <linux/bpf.h>
#include <linux/cgroup.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/spinlock.h>

/* Serializes attach vs detach vs destroy-path release.  Programs are only
 * ever swapped under this lock; the old reference is dropped after unlock
 * (bpf_prog_put() may sleep).  There are no run-path readers. */
static DEFINE_SPINLOCK(cgroup_bpf_stub_lock);

/* Resolve a cgroup-directory fd to its cgroup, holding a css reference.
 * Returns ERR_PTR(-EBADF) for a bad fd or -ENOENT for a dying cgroup.
 *
 * netd passes the cgroup v2 root, which 3.18 cannot mount, so the fd may
 * refer to a plain directory; fall back to the default hierarchy's root
 * cgroup. The program is stored and reference-counted as for a real
 * attach. */
struct cgroup *bpf_cgroup_from_fd(int fd)
{
	struct fd f = fdget(fd);
	struct cgroup_subsys_state *css;
	struct cgroup *cgrp;

	if (!f.file)
		return ERR_PTR(-EBADF);

	/* NULL subsystem yields the cgroup's own css (&cgrp->self) with a
	 * reference held, which pins the cgroup for the attach/detach below. */
	css = css_tryget_online_from_dir(f.file->f_path.dentry, NULL);
	fdput(f);
	if (!IS_ERR(css)) {
		cgrp = css->cgroup;
		return cgrp;
	}
	if (PTR_ERR(css) != -EBADF)
		return ERR_CAST(css);

	cgrp = &cgrp_dfl_root.cgrp;
	if (!css_tryget_online(&cgrp->self))
		return ERR_PTR(-ENOENT);
	return cgrp;
}

void bpf_cgroup_from_fd_put(struct cgroup *cgrp)
{
	css_put(&cgrp->self);
}

/* Store @prog (reference already held by the caller via bpf_prog_get()) in
 * the slot for @type, replacing and putting any program already there. */
int bpf_cgroup_attach_stub(struct cgroup *cgrp, struct bpf_prog *prog,
			   u32 type, u32 flags)
{
	unsigned long irqflags;
	struct bpf_prog *old;

	/* No run path consumes these, so MULTI degrades to replace.
	 * The flags are otherwise ignored. */
	(void)flags;

	if (type >= __MAX_BPF_ATTACH_TYPE)
		return -EINVAL;

	spin_lock_irqsave(&cgroup_bpf_stub_lock, irqflags);
	old = cgrp->bpf_stub_progs[type];
	cgrp->bpf_stub_progs[type] = prog;
	spin_unlock_irqrestore(&cgroup_bpf_stub_lock, irqflags);

	if (old)
		bpf_prog_put(old);

	return 0;
}

int bpf_cgroup_detach_stub(struct cgroup *cgrp, u32 type)
{
	unsigned long irqflags;
	struct bpf_prog *old;

	if (type >= __MAX_BPF_ATTACH_TYPE)
		return -EINVAL;

	spin_lock_irqsave(&cgroup_bpf_stub_lock, irqflags);
	old = cgrp->bpf_stub_progs[type];
	cgrp->bpf_stub_progs[type] = NULL;
	spin_unlock_irqrestore(&cgroup_bpf_stub_lock, irqflags);

	if (!old)
		return -ENOENT;

	bpf_prog_put(old);
	return 0;
}

/* Called from kernel/cgroup.c before a cgroup is freed (and for the embedded
 * root cgroup on hierarchy teardown): drop every stored program reference.
 * Slots start NULL (cgroups come from kzalloc), so this is a no-op for
 * cgroups that never saw an attach. */
void cgroup_bpf_stub_release(struct cgroup *cgrp)
{
	unsigned int type;

	for (type = 0; type < __MAX_BPF_ATTACH_TYPE; type++) {
		struct bpf_prog *prog;
		unsigned long irqflags;

		spin_lock_irqsave(&cgroup_bpf_stub_lock, irqflags);
		prog = cgrp->bpf_stub_progs[type];
		cgrp->bpf_stub_progs[type] = NULL;
		spin_unlock_irqrestore(&cgroup_bpf_stub_lock, irqflags);

		if (prog)
			bpf_prog_put(prog);
	}
}
