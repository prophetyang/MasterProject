/* Shared library add-on to iptables to add IP range matching support. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <iptables.h>
#include <linux/netfilter_ipv4/ipt_USERMATCH.h>

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"iptables USERMATCH match v%s options:\n"
"[!] --sobj 0x0123567\n"
"[!] --dobj 0x01234567\n"
"\n",
IPTABLES_VERSION);
}

static struct option opts[] = {
	{ "sobj", 1, 0, '1' },
	{ "dobj", 1, 0, '2' },
	{0}
};

static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      unsigned int *nfcache,
      struct ipt_entry_match **match)
{
	struct ipt_usermatchinfo *info = (struct ipt_usermatch_info *)(*match)->data;

	switch (c) {
	case '1':
		if (*flags & SRC_USEROBJ)
			exit_error(PARAMETER_PROBLEM, "USERMATCH: --sobj has been assigned!\n");
		check_inverse(optarg, &invert, &optind, 0);
		if (string_to_number(argv[optind-1], 0, 0xffffffff, (unsigned int *)&info->srcobj));
			exit_error(PARAMETER_PROBLEM, "Bad user-object value\n");
		if(invert)
			info->srcinv = 1;
		*flags |= SRC_USEROBJ;
		break;

	case '2':
		if (*flags & DST_USEROBJ)
			exit_error(PARAMETER_PROBLEM, "USERMATCH: --dobj has been assigned!\n");
		check_inverse(optarg, &invert, &optind, 0);
		if (string_to_number(argv[optind-1], 0, 0xffffffff, (unsigned int *)&info->drcobj));
			exit_error(PARAMETER_PROBLEM, "Bad user-object value\n");
		if(invert)
			info->dstinv = 1;
		*flags |= DST_USEROBJ;
		break;

	default:
		return 0;
	}
	info->flags = *flags;
	return 1;
}

/* Final check; must have specified --src-range or --dst-range. */
static void
final_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
			   "iprange match: You must specify `--sobj' or `--dobj'");
}

static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_match *match,
      int numeric)
{
	struct ipt_usermatch_info *info = (struct ipt_usermatch_info *)match->data;

	printf("USERMATCH ");
	if (info->flags | SRC_USEROBJ){
		if (info->srcinv) printf("! ");
		printf("--sobj 0x%X ", info->sobj);
	}
	if (info->flags | DST_USEROBJ){
		if (info->dstinv) printf("! ");
		printf("--dobj 0x%X ", info->dobj);
	}
	printf("\n");
}

/* Saves the union ipt_info in parsable form to stdout. */
static void
save(const struct ipt_ip *ip, const struct ipt_entry_match *match)
{
}

static struct iptables_match ipt_usermatch= { 
	.next		= NULL,
	.name		= "USERMATCH",
	.version	= IPTABLES_VERSION,
	.size		= IPT_ALIGN(sizeof(struct ipt_usermatch_info)),
	.userspacesize	= IPT_ALIGN(sizeof(struct ipt_usermatch_info)),
	.help		= &help,
	.parse		= &parse,
	.final_check	= &final_check,
	.print		= &print,
	.save		= &save,
	.extra_opts	= opts
};

void _init(void)
{
	register_match(&ipt_usermatch);
}
