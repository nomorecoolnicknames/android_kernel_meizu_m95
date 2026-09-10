obj-y := core.o
obj-$(CONFIG_BPF_SYSCALL) += syscall.o verifier.o inode.o arraymap.o hashtab.o helpers.o progtypes.o cgroup_stub.o
ifdef CONFIG_TEST_BPF
obj-$(CONFIG_BPF_SYSCALL) += test_stub.o
endif
