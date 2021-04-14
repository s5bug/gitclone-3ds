#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <3ds.h>
#include <git2.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>

ssize_t readlink(const char *restrict path, char *restrict buf, size_t bufsize);

#define PTR_ALIGN (sizeof(size_t))
#define ONES ((size_t)-1/UCHAR_MAX)
#define HIGHS (ONES * (UCHAR_MAX/2+1))
#define HASZERO(x) ((x)-ONES & ~(x) & HIGHS)

char *__strchrnul(const char *s, int c)
{
	size_t *w, k;

	c = (unsigned char)c;
	if (!c) return (char *)s + strlen(s);

	for (; (uintptr_t)s % PTR_ALIGN; s++)
		if (!*s || *(unsigned char *)s == c) return (char *)s;
	k = ONES * c;
	for (w = (void *)s; !HASZERO(*w) && !HASZERO(*w^k); w++);
	for (s = (void *)w; *s && *(unsigned char *)s != c; s++);
	return (char *)s;
}

#define SYMLOOP_MAX 1
static size_t slash_len(const char *s)
{
	const char *s0 = s;
	while (*s == '/') s++;
	return s-s0;
}

char *
realpath(const char *path, char resolved[PATH_MAX])
{
    char *p, *q, *s;
    size_t left_len = 0, resolved_len = 0;
    char left[PATH_MAX], next_token[PATH_MAX];
    if (path[0] == '/') {
        char drive[PATH_MAX];
        if (getcwd(drive, PATH_MAX) == NULL) {
            strlcpy(resolved, ".", PATH_MAX);
            return (NULL);
        }
        strtok(drive, "/");
        resolved_len = strlcpy(resolved, drive, PATH_MAX);
        strlcat(resolved, "/", PATH_MAX);
        resolved_len++;
        if (path[1] == '\0')
            return (resolved);
        left_len = strlcpy(left, path + 1, sizeof(left));
    } else {
        int i, path_len = strlen(path);
        for (i=0; i<path_len; i++) {
            if (path[i] == '/') {
                if (path[i - 1] == ':') {
                    strncpy(resolved, path, i + 1);
                    resolved_len = i + 1;
                    left_len = strlcpy(left, path + i, sizeof(left));
                } else {
                    i = path_len;
                }
                break;
            }
        }

        if (i == path_len) {
            if (getcwd(resolved, PATH_MAX) == NULL) {
                strlcpy(resolved, ".", PATH_MAX);
                return (NULL);
            }
            resolved_len = strlen(resolved);
            left_len = strlcpy(left, path, sizeof(left));
        }
    }
    if (left_len >= sizeof(left) || resolved_len >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return (NULL);
    }
    /*
     * Iterate over path components in `left'.
     */
    while (left_len != 0) {
        /*
         * Extract the next path component and adjust `left'
         * and its length.
         */
        p = strchr(left, '/');
        s = p ? p : left + left_len;
        if (s - left >= sizeof(next_token)) {
            errno = ENAMETOOLONG;
            return (NULL);
        }
        memcpy(next_token, left, s - left);
        next_token[s - left] = '\0';
        left_len -= s - left;
        if (p != NULL)
            memmove(left, s + 1, left_len + 1);
        if (resolved[resolved_len - 1] != '/') {
            if (resolved_len + 1 >= PATH_MAX) {
                errno = ENAMETOOLONG;
                return (NULL);
            }
            resolved[resolved_len++] = '/';
            resolved[resolved_len] = '\0';
        }
        if (next_token[0] == '\0')
            continue;
        else if (strcmp(next_token, ".") == 0)
            continue;
        else if (strcmp(next_token, "..") == 0) {
            /*
             * Strip the last path component except when we have
             * single "/"
             */
            if (resolved_len > 1) {
                resolved[resolved_len - 1] = '\0';
                q = strrchr(resolved, '/') + 1;
                *q = '\0';
                resolved_len = q - resolved;
            }
            continue;
        }
        /*
         * Append the next path component and lstat() it. If
         * lstat() fails we still can return successfully if
         * there are no more path components left.
         */
        resolved_len = strlcat(resolved, next_token, PATH_MAX);
        if (resolved_len >= PATH_MAX) {
            errno = ENAMETOOLONG;
            return (NULL);
        }
    }
    /*
     * Remove trailing slash except when the resolved pathname
     * is a single "/".
     */
    int just_drive = 0;
    for (int i=0; i<resolved_len; i++) {
        if (resolved[i] == '/' && resolved[i - 1] == ':' && ++just_drive > 1)
            break;
    }
    if (resolved_len > 1 && resolved[resolved_len - 1] == '/' && just_drive > 1)
        resolved[resolved_len - 1] = '\0';
    return (resolved);
}

ssize_t readlink(const char *restrict path, char *restrict buf, size_t bufsize) {
    errno = EINVAL;
    return -1;
}

ssize_t symlink(const char *path1, const char *path2) {
    errno = ENOSYS;
    return -1;
}

char *p_realpath(const char *pathname, char *resolved)
{
	char *ret;
	if ((ret = realpath(pathname, resolved)) == NULL)
		return NULL;

#ifdef __OpenBSD__
	/* The OpenBSD realpath function behaves differently,
	 * figure out if the file exists */
	if (access(ret, F_OK) < 0)
		ret = NULL;
#endif
	return ret;
}

uid_t getuid(void) {
    return 0;
}

uid_t geteuid(void) {
    return 0;
}

struct passwd {};

int getpwuid_r(uid_t uid, struct passwd *pwd, char *buffer, size_t bufsize, struct passwd **result) {
    return EIO;
}

long sysconf(int name) {
    errno = EINVAL;
    return -1;
}

mode_t umask(mode_t cmask) {
    return 0777;
}

#define UNUSED(x) (void)(x)

static int readline(char **out)
{
	int c, error = 0, length = 0, allocated = 0;
	char *line = NULL;

	errno = 0;

	while ((c = getchar()) != EOF) {
		if (length == allocated) {
			allocated += 16;

			if ((line = realloc(line, allocated)) == NULL) {
				error = -1;
				goto error;
			}
		}

		if (c == '\n')
			break;

		line[length++] = c;
	}

	if (errno != 0) {
		error = -1;
		goto error;
	}

	line[length] = '\0';
	*out = line;
	line = NULL;
	error = length;
error:
	free(line);
	return error;
}

static int ask(char **out, const char *prompt, char optional)
{
	printf("%s ", prompt);
	fflush(stdout);

	if (!readline(out) && !optional) {
		fprintf(stderr, "Could not read response: %s", strerror(errno));
		return -1;
	}

	return 0;
}

int cred_acquire_cb(git_credential **out,
		const char *url,
		const char *username_from_url,
		unsigned int allowed_types,
		void *payload)
{
	char *username = NULL, *password = NULL, *privkey = NULL, *pubkey = NULL;
	int error = 1;

	UNUSED(url);
	UNUSED(payload);

	if (username_from_url) {
		if ((username = strdup(username_from_url)) == NULL)
			goto out;
	} else if ((error = ask(&username, "Username:", 0)) < 0) {
		goto out;
	}

	if (allowed_types & GIT_CREDENTIAL_SSH_KEY) {
		int n;

		if ((error = ask(&privkey, "SSH Key:", 0)) < 0 ||
		    (error = ask(&password, "Password:", 1)) < 0)
			goto out;

		if ((n = snprintf(NULL, 0, "%s.pub", privkey)) < 0 ||
		    (pubkey = malloc(n + 1)) == NULL ||
		    (n = snprintf(pubkey, n + 1, "%s.pub", privkey)) < 0)
			goto out;

		error = git_credential_ssh_key_new(out, username, pubkey, privkey, password);
	} else if (allowed_types & GIT_CREDENTIAL_USERPASS_PLAINTEXT) {
		if ((error = ask(&password, "Password:", 1)) < 0)
			goto out;

		error = git_credential_userpass_plaintext_new(out, username, password);
	} else if (allowed_types & GIT_CREDENTIAL_USERNAME) {
		error = git_credential_username_new(out, username);
	}

out:
	free(username);
	free(password);
	free(privkey);
	free(pubkey);
	return error;
}

#define PRIuZ "zu"

volatile void * git___load(void * volatile *ptr)
{
	return *ptr;
}

typedef struct progress_data {
	git_indexer_progress fetch_progress;
	size_t completed_steps;
	size_t total_steps;
	const char *path;
} progress_data;

static void print_progress(const progress_data *pd)
{
	int network_percent = pd->fetch_progress.total_objects > 0 ?
		(100*pd->fetch_progress.received_objects) / pd->fetch_progress.total_objects :
		0;
	int index_percent = pd->fetch_progress.total_objects > 0 ?
		(100*pd->fetch_progress.indexed_objects) / pd->fetch_progress.total_objects :
		0;

	int checkout_percent = pd->total_steps > 0
		? (int)((100 * pd->completed_steps) / pd->total_steps)
		: 0;
	size_t kbytes = pd->fetch_progress.received_bytes / 1024;

	if (pd->fetch_progress.total_objects &&
		pd->fetch_progress.received_objects == pd->fetch_progress.total_objects) {
		printf("Resolving deltas %u/%u\r",
		       pd->fetch_progress.indexed_deltas,
		       pd->fetch_progress.total_deltas);
	} else {
		printf("net %3d%% (%4" PRIuZ " kb, %5u/%5u)  /  idx %3d%% (%5u/%5u)  /  chk %3d%% (%4" PRIuZ "/%4" PRIuZ")%s\n",
		   network_percent, kbytes,
		   pd->fetch_progress.received_objects, pd->fetch_progress.total_objects,
		   index_percent, pd->fetch_progress.indexed_objects, pd->fetch_progress.total_objects,
		   checkout_percent,
		   pd->completed_steps, pd->total_steps,
		   pd->path);
	}
}

static int sideband_progress(const char *str, int len, void *payload)
{
	(void)payload; /* unused */

	printf("remote: %.*s", len, str);
	fflush(stdout);
	return 0;
}

static int fetch_progress(const git_indexer_progress *stats, void *payload)
{
	progress_data *pd = (progress_data*)payload;
	pd->fetch_progress = *stats;
	print_progress(pd);
	return 0;
}
static void checkout_progress(const char *path, size_t cur, size_t tot, void *payload)
{
	progress_data *pd = (progress_data*)payload;
	pd->completed_steps = cur;
	pd->total_steps = tot;
	pd->path = path;
	print_progress(pd);
}


int lg2_clone(git_repository *repo, int argc, char **argv)
{
	progress_data pd = {{0}};
	git_repository *cloned_repo = NULL;
	git_clone_options clone_opts = GIT_CLONE_OPTIONS_INIT;
	git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
	const char *url = argv[1];
	const char *path = argv[2];
	int error;

	(void)repo; /* unused */

	/* Validate args */
	if (argc < 3) {
		printf ("USAGE: %s <url> <path>\n", argv[0]);
		return -1;
	}

	/* Set up options */
	checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE;
	checkout_opts.progress_cb = checkout_progress;
	checkout_opts.progress_payload = &pd;
	clone_opts.checkout_opts = checkout_opts;
	clone_opts.fetch_opts.callbacks.sideband_progress = sideband_progress;
	clone_opts.fetch_opts.callbacks.transfer_progress = &fetch_progress;
	clone_opts.fetch_opts.callbacks.credentials = cred_acquire_cb;
	clone_opts.fetch_opts.callbacks.payload = &pd;

	/* Do the clone */
	error = git_clone(&cloned_repo, url, path, &clone_opts);
	printf("\n");
	if (error != 0) {
		const git_error *err = git_error_last();
		if (err) printf("ERROR %d: %s\n", err->klass, err->message);
		else printf("ERROR %d: no detailed info\n", error);
	}
	else if (cloned_repo) git_repository_free(cloned_repo);
	return error;
}

void cloneThread(void* arg) {
	printf("Starting clone...\n");

    char* args[] = { "clone", "https://github.com/s5bug/calculo.git", "sdmc:/calculo" };

	lg2_clone(NULL, 3, args);
}

bool networkAvailable() {
	u32 wifi = 0;
	if (R_FAILED (ACU_GetWifiStatus(&wifi)) || !wifi) {
		return false;
	}

	return true;
}

bool haveWifi = false;

void testWifi() {
	if(!haveWifi && networkAvailable()) {
		printf("WiFi Acquired.\n");
		threadCreate(cloneThread, NULL, 0x10000, 0x3F, 0, true);
		haveWifi = true;
	}
}

int main(int argc, char* argv[])
{
	acInit();
	ptmuInit();

	git_libgit2_init();

	gfxInitDefault();
	consoleInit(GFX_TOP, NULL);

	// Main loop
	while (aptMainLoop())
	{
		testWifi();

		gspWaitForVBlank();
		gfxSwapBuffers();
		hidScanInput();

		// Your code goes here
		u32 kDown = hidKeysDown();
		if (kDown & KEY_START)
			break; // break in order to return to hbmenu
	}

	gfxExit();

	git_libgit2_shutdown();

	ptmuExit();
	acExit();
	return 0;
}
