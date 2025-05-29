#include <argp.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define BAUD_RATE B115200           // Set baud rate
#define START_BYTE 0xAA
#define TIMEOUT_MS 100 // Timeout in milliseconds

#define MAX_DATA_LEN 128
#define SERIAL_TIMEOUT_SEC 2

const char *argp_program_version = "bootloader-uart 1.0";
const char *argp_program_bug_address = "<your-email>";
static char doc[] = "A simple UART bootloader for STM32.";
static char args_doc[] = "FILE";

#ifdef d
#undef d
#endif

typedef union __attribute__((packed))
{
    uint32_t d[2];
    uint16_t w[4];
    uint8_t  v[8];
} u64_Val;

volatile sig_atomic_t keep_running = 1;

static error_t parse_opt(int key, char *arg, struct argp_state *state);
u64_Val add (u64_Val x, u64_Val y);
u64_Val xor (u64_Val x, u64_Val y);
u64_Val rotateLeft(u64_Val x, uint8_t n);
void crypto (uint8_t *rand, uint8_t *code);
void handle_exit_signal(int sig);

static struct argp_option options[] = {
    {"port",  'p', "PORT", 0, "UART device (e.g., /dev/ttyUSB0)" },
    {"baud",  'b', "BAUD", 0, "Baud rate (default: 115200)" },
    {"file",  'f', "FILE", 0, "Path to a binary file" },
    { 0 }
};

struct arguments {
    char *port;
    int baud;
    char *filename;
};

typedef	struct {
	uint8_t start;
	uint8_t length;
	uint8_t header;
	uint8_t data[128];
	uint8_t checksum;
} Packet_t;

enum Packet_Header {
	ack_ok = 0,
	checksum_error,
    data_req,
	data_packet,
	data_size,
    data,
	challenge,
	challenge_pass,
	challenge_fail
};

typedef enum {
    READY = 0,
    AUTH,
    UPLOADING_A,
    UPLOADING_B,
} State_t;

enum FW {
	FWA = 0,
	FWB,
	FWAB
};

static struct argp argp = {
    options,
    parse_opt,
    args_doc,
    doc
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *args = state->input;
    switch (key) {
        case 'p': args->port = arg; break;
        case 'b': args->baud = atoi(arg); break;
        case 'f': args->filename = arg; break;
        default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

int configure_serial_port(char* device_path)
{
    int fd = open(device_path, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    struct termios tty;
    if (tcgetattr(fd, &tty) != 0) {
        perror("tcgetattr");
        close(fd);
        return -1;
    }

    cfsetospeed(&tty, B115200);
    cfsetispeed(&tty, B115200);

    tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;  // 8-bit chars
    tty.c_iflag &= ~IGNBRK;                      // disable break processing
    tty.c_lflag = 0;                             // no signaling chars, no echo
    tty.c_oflag = 0;                             // no remapping, no delays
    tty.c_cc[VMIN]  = 0;                         // non-blocking read
    tty.c_cc[VTIME] = SERIAL_TIMEOUT_SEC * 10;   // read timeout (deciseconds)

    tty.c_iflag &= ~(IXON | IXOFF | IXANY);      // shut off xon/xoff ctrl
    tty.c_cflag |= (CLOCAL | CREAD);             // ignore modem controls
    tty.c_cflag &= ~(PARENB | PARODD);           // no parity
    tty.c_cflag &= ~CSTOPB;
//  tty.c_cflag &= ~CRTSCTS;                     // no hw flow control

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        perror("tcsetattr");
        close(fd);
        return -1;
    }

    return fd;
}


int receive_packet(int fd, Packet_t *p) {
    uint8_t byte;
    fd_set fds;
    struct timeval timeout;

    // Wait for START_BYTE
    while (1) {
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        timeout.tv_sec = SERIAL_TIMEOUT_SEC;
        timeout.tv_usec = 0;

        int ret = select(fd + 1, &fds, NULL, NULL, &timeout);
        if (ret <= 0) return -1;

        if (read(fd, &byte, 1) == 1 && byte == START_BYTE) break;
    }

    if (read(fd, &p->length, 1) != 1) return -2;
    if (read(fd, &p->header, 1) != 1) return -3;
    if (p->length > MAX_DATA_LEN) return -4;

    uint8_t checksum = p->length ^ p->header;

    ssize_t got = read(fd, &p->data[0], p->length);
    if (got != p->length) return -5;

    for (uint8_t i = 0; i < p->length; ++i)
        checksum ^= p->data[i];

    if (read(fd, &p->checksum, 1) != 1) return -6;

    if (p->checksum != checksum){
        printf("  p->checksum: %02X", p->checksum);
        printf("  checksum: %02X\n", checksum);
        return -7;
    }

    return 0;
}

void encode(uint8_t *c, uint8_t *r, uint8_t n)
{
    memcpy(r, c, n);
}

void authenticate(Packet_t *chlng, Packet_t *res)
{
    res->start = START_BYTE;
    res->length = 8;
    res->header = challenge;
    res->checksum = res->header ^ res->length;
    crypto(chlng->data, res->data);
    for (int i = 0; i < res->length; i++) {
        res->checksum ^= res->data[i];
    }
}

int send_packet(int fd, Packet_t *p)
{
    if (p == NULL) return -1;

    uint8_t buffer[1 + 1 + 1 + p->length + 1];

    buffer[0] = START_BYTE;
    buffer[1] = p->length;
    buffer[2] = p->header;

    for (uint8_t i = 0; i < p->length; ++i) {
        buffer[3 + i] = p->data[i];
    }

    buffer[3 + p->length] = p->checksum;

    ssize_t sent = write(fd, buffer, p->length + 4);
    return (sent == p->length + 4) ? 0 : -1;
}

void bin_size(int bin_fd, Packet_t *packet, uint32_t *full_size, uint16_t *packet_num, uint16_t *page_num, uint16_t *rem)
{
    #define PAGE_SIZE 0x800
    *full_size = lseek(bin_fd, 0, SEEK_END);

    *page_num = *full_size/PAGE_SIZE;
    *rem = *full_size % PAGE_SIZE;
    *packet_num = (*full_size + MAX_DATA_LEN + 1) / MAX_DATA_LEN; // ceiling division

    packet->start = START_BYTE;
    packet->length = 10;
    packet->header = data_size;

    packet->checksum = packet->header ^ packet->length;

    *(uint32_t *)&packet->data[0] = *full_size;
    *(uint16_t *)&packet->data[4] = *page_num;
    *(uint16_t *)&packet->data[6] = *rem / MAX_DATA_LEN;
    *(uint16_t *)&packet->data[8] = *packet_num;

    for (int i = 0; i < packet->length; i++) {
        packet->checksum ^= packet->data[i];
    }

    lseek(bin_fd, 0, SEEK_SET);
}

bool prepare_pkt(const int bin_fd, Packet_t *packet, const uint16_t *rem, const uint16_t *pkt_num, uint16_t *pkt_cnt)
{
    if (packet == NULL )
        return false;


    packet->start = START_BYTE;
    packet->length = (*pkt_cnt == *pkt_num) ? *rem : MAX_DATA_LEN;
    packet->header = data;
    packet->checksum = packet->header ^ packet->length;
    int data_read = read(bin_fd, packet->data, packet->length);
    if(data_read > 0) {
        for (int i = 0; i < packet->length; i++) {
            packet->checksum ^= packet->data[i];
        }
    }
    return true;
}

void print_packet(Packet_t *packet)
{
    printf("\n");
    printf("start: 0x%02X header: 0x%02X, length: %d\n",packet->start, packet->header, packet->length);
    for (int i = 0; i < packet->length; ++i)
        printf(" %02X", packet->data[i]);
    printf(", %02X", packet->checksum);
    printf("\n");
}

void progress(uint32_t total, uint32_t prog)
{
// for (int i = 0; i <= TOTAL; i++) {
        printf("\r[");  // carriage return
        for (int j = 0; j < total; j++) {
            if (j < prog)
                printf("#");
            else
                printf(" ");
        }
        printf("] %3d%%", (prog * 100) / total);
        fflush(stdout);
}

void waiting(void)
{
    static uint8_t w = 0;

    printf("\rWaiting");
    for (int i = 0; i <= w; i++) {
        printf(".");
    }

    printf("   ");
    fflush(stdout);

    w = (w + 1) % 3;
}
const uint8_t *memstr(const uint8_t *haystack, size_t hlen, const char *needle)
{
    size_t nlen = strlen(needle);
    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (memcmp(haystack + i, needle, nlen) == 0)
            return haystack + i;
    }
    return NULL;
}

uint8_t *extract(const char *label, const uint8_t *data, uint32_t total_len, uint32_t *out_len)
{
    char pattern[32];
    snprintf(pattern, sizeof(pattern), "%s##", label);
    const uint8_t *start = memstr(data, total_len, pattern);
    if (!start) return NULL;

    // Move past "LABEL##"
    start += strlen(pattern);

    // Convert the next ASCII characters to an int (length)
    int len = atoi((const char *)start);
    *out_len = len;

    // Find the "##" separator
    const uint8_t *bin_start = memstr(start, total_len - (start - data), "##");
    if (!bin_start) return NULL;

    // Move past the "##"
    bin_start += 2;

    return (uint8_t *)bin_start;
}

int extract_fwtmp(const char *pkg, uint8_t *bina, uint32_t *size_a, uint8_t *binb, uint32_t *size_b)
{
    char tmpname_a[] = "/tmp/fwaXXXXXX";
    char tmpname_b[] = "/tmp/fwbXXXXXX";

    int fda = mkstemp(tmpname_a);
    if (fda == -1) {
        perror("mkstemp failed");
        return -1;
    }

    int fdb = mkstemp(tmpname_b);
    if (fda == -1) {
        perror("mkstemp B failed");
        close(fda);
        unlink(tmpname_a);
        return -1;
    }

    int fdpkg = open(pkg, O_RDONLY);
    if (fdpkg < 0) return -1;

    int pkg_size = lseek(fdpkg, 0, SEEK_END);
    lseek(fdpkg, 0, SEEK_SET);

    uint8_t *data = malloc(pkg_size);
    if (!data) goto error;

    if (read(fdpkg, data, pkg_size) != pkg_size) goto error;

    uint8_t *pA = extract("APP_A", data, pkg_size, size_a);

    uint8_t *pB = extract("APP_B", data, pkg_size, size_b);
    if (!pA || !pB) goto error;

    if (write(fda, pA, *size_a) != *size_a) goto error;
    if (write(fdb, pB, *size_b) != *size_b) goto error;

    printf("Extracted: %s (%u bytes), %s (%u bytes)\n", tmpname_a, *size_a, tmpname_b, *size_b);

    snprintf(bina, strlen(tmpname_a) + 1, tmpname_a);
    snprintf(binb, strlen(tmpname_b) + 1, tmpname_b);

    close(fdpkg);
    close(fda);
    close(fdb);
    free(data);
    return 0;

error:
    perror("extract_fwtmp");
    if (fda >= 0) close(fda);
    if (fdb >= 0) close(fdb);
    if (fdpkg >= 0) close(fdpkg);
    free(data);
    return -1;
}

int main(int argc, char **argv)
{
    struct arguments args = { "/dev/ttyUSB0", 115200 };

    int bina_fd;
    int binb_fd;
    uint32_t size_a = 0, size_b = 0;
    uint8_t binfile_a[32] = "\0";
    uint8_t binfile_b[32] = "\0";

    enum FW fw;

    signal(SIGINT, handle_exit_signal);   // Ctrl+C
    signal(SIGTERM, handle_exit_signal);  // kill <pid>

    argp_parse(&argp, argc, argv, 0, 0, &args);
    printf("Using port: %s, baud: %d, file: %s \n", args.port, args.baud, args.filename);

    int fd = configure_serial_port(args.port);
    if (fd < 0) {
        printf("Failed to configure device %s \n", args.port);
        return 1;
    }

    if (strstr(args.filename,"pkg") != NULL) {
        if (extract_fwtmp(args.filename, binfile_a, &size_a, binfile_b, &size_b) != 0) {
            printf("NOT a correct pkg file: %s \n", args.filename);
            return 1;
        }
        bina_fd = open(binfile_a, O_RDONLY);
        if (bina_fd < 0) {
            printf("Failed to open binary file %s \n", binfile_a);
            return 1;
        }
        binb_fd = open(binfile_b, O_RDONLY);
        if (binb_fd < 0) {
            printf("Failed to open binary file %s \n", binfile_b);
            return 1;
        }
        fw = FWAB;
    } else if (strstr(args.filename, "_A.bin") != NULL) {
        bina_fd = open(args.filename, O_RDONLY);
        if (bina_fd < 0) {
            printf("Failed to open binary file %s \n", args.filename);
            return 1;
        }
        fw = FWA;
    } else if (strstr(args.filename, "_B.bin") != NULL) {
        binb_fd = open(args.filename, O_RDONLY);
        if (binb_fd < 0) {
            printf("Failed to open binary file %s \n", args.filename);
            return 1;
        }
        fw = FWB;
    } else {
        printf("NOT a correct file name: %s \n", args.filename);
    }
/*


*/

    State_t state = READY;

    int ret = 0;
    Packet_t packet;

    uint32_t full_size = 0;
    uint16_t page_num = 0;
    uint16_t rem = 0;
    uint16_t packet_num = 0;
    uint16_t pkt_count = 0;

    while(keep_running) {
        ret = receive_packet(fd, &packet);
        if (ret == 0) {
            //print_packet(&packet);
            switch(packet.header) {
                case ack_ok:
                    {
                        Packet_t packet;
                        if ((state == UPLOADING_A || state == UPLOADING_B) && pkt_count < packet_num) {
                            if (pkt_count == 0) printf("Progress:\n");
                            int bin_fd=(state == UPLOADING_A) ? bina_fd : binb_fd;
                            prepare_pkt(bin_fd, &packet, &rem, &packet_num, &pkt_count);
                            send_packet(fd, &packet);
                            progress(100, (pkt_count * 100/packet_num));
                            pkt_count++;
                        }
                        if ((state == UPLOADING_A || UPLOADING_B) && pkt_count == packet_num) {
                            if ((state == UPLOADING_A && fw == FWA ) ||
                                (state == UPLOADING_B && fw == FWB ) ||
                                (state == UPLOADING_B && fw == FWAB) ) state = READY;
                            printf("\nDone.\n\n");
                            fflush(stdout);
                            pkt_count = 0;
                        }
                    }
                    break;
                case checksum_error:
                    pkt_count = 0;
                    break;
                case data_req:
                    break;
                case data_packet:
                    break;
                case data_size:
                    break;
                case data:
                    break;
                case challenge:
                    {
                        state = AUTH;
                        Packet_t response;
                        authenticate(&packet, &response);
                       // print_packet(&packet);
                       // print_packet(&response);
                        send_packet(fd, &response);
                        break;
                    }
                    case challenge_pass:
                    {
                        int bin_fd;
                        if (packet.data[0] == FWA) {
                            state = UPLOADING_A;
                            bin_fd = bina_fd;
                            printf("Uploading binary A:  %s \n", binfile_a);
                        } else {
                            state = UPLOADING_B;
                            bin_fd = binb_fd;
                            printf("Uploading binary B:  %s \n", binfile_b);
                        }
                        Packet_t pkt_size;
                        bin_size(bin_fd, &pkt_size, &full_size, &packet_num, &page_num, &rem);
                        printf("full size: %d  pkt num: %d page num: %d pkt rem: %d \n", full_size, packet_num, page_num, rem/MAX_DATA_LEN);
                        send_packet(fd, &pkt_size);
                    }
                    break;
                case challenge_fail:
                    pkt_count = 0;
                    break;
                default:
            }
        } else {
            waiting();
        }
    }

    printf("cleaning up...\n");

    unlink(binfile_a);
    unlink(binfile_b);
    close(fd);
    close(bina_fd);
    close(binb_fd);
    return 0;
}

void handle_exit_signal(int sig)
{
    printf("\nCaught signal %d\n", sig);
    keep_running = 0;
}

u64_Val rotateLeft(u64_Val x, uint8_t n)
{
    n %= 64;
    if (n == 0) return x;

    uint64_t temp = ((uint64_t)x.d[1] << 32) | x.d[0];
    temp = (temp << n) | (temp >> (64 - n));

    u64_Val z;
    z.d[0] = (uint32_t)(temp & 0xFFFFFFFF);
    z.d[1] = (uint32_t)(temp >> 32);
    return z;
}

void crypto (uint8_t *rand, uint8_t *code)
{
    u64_Val x;
    u64_Val y;
    u64_Val constant;

    constant.d[0] = 0xb17834df;
    constant.d[1] = 0x5461a928;

    memset(&y, 0, sizeof(y));

    u64_Val rand_val;
    for (int i = 0; i < 8; ++i)
        rand_val.v[i] = rand[i];

    x = xor(add(rand_val, constant), constant);

    for (uint8_t i = 0; i < 33; ++i)
    {
    	u64_Val tmp = add(x, y);
    	x = xor(tmp, rotateLeft(constant, i));
    	y = xor( constant, add(constant, xor(x, constant)));
        x = xor( x, y);
        x = add(x, xor( add(constant, x) , y));
    }

    for (uint8_t i = 0; i < 8; ++i)
    	code[i] = x.v[i];
}

u64_Val xor (u64_Val x, u64_Val y)
{
    u64_Val z;

    z.d[0] = x.d[0] ^ y.d[0];
    z.d[1] = x.d[1] ^ y.d[1];

    return (z);
}


u64_Val add(u64_Val x, u64_Val y)
{
    u64_Val z;

    z.d[0] = x.d[0] + y.d[0];

    // Carry occurred if sum is smaller than either operand
    uint8_t carry = (z.d[0] < x.d[0]) ? 1 : 0;

    z.d[1] = x.d[1] + y.d[1] + carry;

    return z;
}
