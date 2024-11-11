#include <linux/console.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/sysrq.h>
#include <linux/termios.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <asm/irq.h>
#include <asm/poll.h>

#include <user/fs.h>
#include <user/user.h>

static struct tty_driver *stdio_driver;
struct tty_port stdio_port;
static struct tty_driver *stupid_driver;
struct tty_port stupid_port;

static int stdio_tty_open(struct tty_struct *tty, struct file *filp)
{
	return tty_port_open(&stdio_port, tty, filp);
}
static void stdio_tty_close(struct tty_struct *tty, struct file *filp)
{
	tty_port_close(&stdio_port, tty, filp);
}
static void stdio_tty_hangup(struct tty_struct *tty)
{
	tty_port_hangup(&stdio_port);
}

static ssize_t write_full(int fd, const char *data, size_t len)
{
	size_t total = 0;
	while (total < len) {
		ssize_t res = host_write(fd, data + total, len - total);
		if (res == -EAGAIN || res == -EINTR)
			/* this is a busy loop...fuck */
			/* TODO: irq on stdout @unshippable */
			continue;
		if (res < 0)
			return res;
		total += res;
	}
	return total;
}

static int stdio_tty_write(struct tty_struct *tty, const unsigned char *data, int len)
{
	ssize_t res = write_full(STDOUT_FD, data, len);
	BUG_ON(res > 0 && res != len);
	return res;
}

static unsigned int stdio_tty_write_room(struct tty_struct *tty)
{
	return 4096; /* bruh we don't buffer */
}

static const struct tty_operations stdio_ops = {
	.open = stdio_tty_open,
	.close = stdio_tty_close,
	.hangup = stdio_tty_hangup,
	.write = stdio_tty_write,
	.write_room = stdio_tty_write_room,
};

static irqreturn_t stdin_irq(int irq, void *dev_id)
{
	struct tty_port *port = dev_id;
	char c, rq;
	while (host_read(STDIN_FD, &c, 1) > 0) {
		rq = 0;
		// meta => sysrq
		if (c == '\x1b') {
			if (host_read(STDIN_FD, &rq, 1) > 0) {
				if ((rq >= 'a' && rq <= 'z') || (rq >= '0' && rq <= '9')) {
					__handle_sysrq(rq, false);
					continue;
				}
			}
		}
		tty_insert_flip_char(port, c, TTY_NORMAL);
		if (rq)
			tty_insert_flip_char(port, rq, TTY_NORMAL);
	}
	tty_flip_buffer_push(port);
	return IRQ_HANDLED;
}

static void sync_window_size(struct tty_struct *tty, int fd)
{
	struct winsize ws = {};
	int err = termio_getwinsz(fd, &ws.ws_col, &ws.ws_row);
	if (err < 0)
		return;
	tty_do_resize(tty, &ws);
}

static int stdio_activate(struct tty_port *port, struct tty_struct *tty)
{
	int err;
	if (port->client_data == NULL) {
		static struct fd_listener listener = {.irq = STDIN_IRQ};

		err = fd_set_nonblock(STDIN_FD);
		if (err < 0)
			return err;
		err = fd_listen(STDIN_FD, POLLIN, &listener);
		if (err < 0)
			return err;
		port->client_data = &listener;

		termio_make_raw(STDIN_FD);
		sync_window_size(tty, STDIN_FD);
	}
	return 0;
}
static const struct tty_port_operations stdio_port_ops = {
	.activate = stdio_activate,
};

static void stdio_console_write(struct console *console, const char *data, unsigned len)
{
	/* TODO this still kinda sucks */
	
	while (len) {
		const char *newline = memchr(data, '\n', len);
		if (newline != NULL) {
			write_full(STDERR_FD, data, newline - data);
			write_full(STDERR_FD, "\r\n", 2);
			len -= newline - data + 1;
			data = newline + 1;
		} else {
			write_full(STDERR_FD, data, len);
			len = 0;
		}
	}
}
static struct tty_driver *stdio_console_device(struct console *console, int *index)
{
	*index = console->index;
	return stdio_driver;
}

static struct console stdio_console = {
	.name = "tty",
	.write = stdio_console_write,
	.device = stdio_console_device,
	.flags = CON_PRINTBUFFER|CON_ANYTIME,
	.index = -1,
};

DECLARE_WAIT_QUEUE_HEAD(hang_queue);

static int stupid_open_hang(struct tty_struct *tty, struct file *filp)
{
	DEFINE_WAIT(wait);
	tty->port = &stupid_port;
	prepare_to_wait(&hang_queue, &wait, TASK_INTERRUPTIBLE);
	while (!signal_pending(current)) {
		schedule();
	}
	finish_wait(&hang_queue, &wait);
	return -EINTR;
}

static struct tty_operations stupid_ops = {
	.open = stupid_open_hang,
};

static __init int stdio_init(void)
{
	int i, err;
	extern char *envp_init[];
	static char TERM_ENV[100] = "TERM=";

	tty_port_init(&stdio_port);
	stdio_port.ops = &stdio_port_ops;

	err = request_irq(STDIN_IRQ, stdin_irq, 0, "stdin", &stdio_port);
	if (err) {
		pr_err("stdin: failed to request_irq: %d\n", err);
		return err;
	}

	stdio_driver = tty_alloc_driver(1, TTY_DRIVER_REAL_RAW |
		TTY_DRIVER_RESET_TERMIOS); /* TODO more than 1 */
	if (!stdio_driver)
		return -ENOMEM;

	stdio_driver->driver_name = "stdio";
	stdio_driver->name = "tty";
	stdio_driver->name_base = 1;
	stdio_driver->major = TTY_MAJOR;
	stdio_driver->minor_start = 1;
	stdio_driver->type = TTY_DRIVER_TYPE_CONSOLE;
	stdio_driver->subtype = SYSTEM_TYPE_CONSOLE;
	stdio_driver->init_termios = tty_std_termios;
	tty_set_operations(stdio_driver, &stdio_ops);
	tty_port_link_device(&stdio_port, stdio_driver, 0);

	if (tty_register_driver(stdio_driver))
		pr_err("stdio: failed to tty_register_driver");

	stupid_driver = tty_alloc_driver(5, 0);
	stupid_driver->driver_name = "stupid";
	stupid_driver->name = "tty";
	stupid_driver->name_base = 2;
	stupid_driver->major = TTY_MAJOR;
	stupid_driver->minor_start = 2;
	tty_set_operations(stupid_driver, &stupid_ops);
	for (i = 0; i < 5; i++)
		tty_port_link_device(&stupid_port, stupid_driver, i);
	if (tty_register_driver(stupid_driver))
		panic("failed to register stupid driver");

	register_console(&stdio_console);

	for (i = 0; envp_init[i]; i++) {
		if (strncmp(TERM_ENV, envp_init[i], strlen(TERM_ENV)) == 0) {
			const char *term_env = host_getenv("TERM");
			strcat(TERM_ENV, term_env ? term_env : "linux");
			envp_init[i] = TERM_ENV;
			break;
		}
	}
	return 0;
}
late_initcall(stdio_init);
