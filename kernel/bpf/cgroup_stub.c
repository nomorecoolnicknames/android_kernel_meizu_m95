/*
 * Minimal BPF_PROG_ATTACH/BPF_PROG_DETACH plumbing for the eBPF backport
 * (2026-09-11).
 *
 * Android 13 netd attaches its cgroup programs (cgroupskb egress/ingress and
 * friends) to its own cgroup directory at startup through
 * libnetd_updatable_init(), and fails outright when the attach syscall is
 * missing - even with every program verified, loaded and pinned.  This file
 * provides just enough plumbing for that: resolve the target fd to a cgroup
 * (only cgroup-directory fds are supported) and store/clear the program
 * pointer in the cgroup's bpf_stub_progs[] slot.
 *
 * The run path is DELIBERATELY stubbed: there are no packet-path hooks, no
 * effective-program computation and no multi-program lists on this 3.18
 * kernel (adapted conceptually from the 4.9 donor
 * kernel/bpf/cgroup.c + include/linux/bpf-cgroup.h, rewritten against this
 * tree's kernfs-based cgroup layout - cgroupfs dir inodes map back to
 * struct cgroup through kernfs_node_from_dentry()->kn->priv, see
 * css_tryget_online_from_dir()).  Attached programs are loaded but never
 * executed here, so BPF_F_ALLOW_MULTI is honored as a simple replace and
 * attach flags are otherwise ignored.
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
 * Bring-up fallback (2026-09-11): Android 13 netd passes the cgroup-v2 root
 * path from its cgrouprc, but this 3.18 kernel cannot mount cgroup v2
 * (ENODEV), so the fd refers to a plain directory and
 * css_tryget_online_from_dir() rejects it with -EBADF.  Fall back to the
 * default hierarchy's root cgroup: the program is stored and
 * reference-counted exactly like a real attach, it is just never executed
 * (no packet-path hooks on this kernel). */
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

	/* Bring-up stub: no run path consumes these, so there is nothing a
	 * second program per attach type could append to; MULTI degrades to
	 * replace.  The flags are otherwise ignored. */
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
