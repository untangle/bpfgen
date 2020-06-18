#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>

#include "managers/imrManager.h"

static int seq; 

/*
	Read in the bpf configuration file, translate it to the IMR, and load the IMR BPF program. 
	@return The return code after doing translation to IMR and loading the BPF program
*/
static int sdwan2bpf(int run_bootstrap)
{
	//Initialize variables 
	json_t *bpf_settings;
	seq = time(NULL);
	struct imr_state *state;
	int ret;

	//Read in /etc/config/bpf.json which describes rules to translates 
	bpf_settings = read_bpf_file();
	if (bpf_settings == NULL) 
	{
		return 1;
	}

	//Read in ruleset from the file descriptor 
	state = imr_ruleset_read(bpf_settings, run_bootstrap);
	if (state == NULL) {
		perror("ruleset_read: ");
		exit(EXIT_FAILURE);
	}

	//Release json object that is no longer needed
	json_decref(bpf_settings);

	//Translate IMR to BPF and load BPF program
	//ret = 0;
	//if (!run_bootstrap)
		ret = imr_do_bpf(state);

	//Free memory
	imr_state_free(state);

	return ret;
}

//Main function
int main(int argc, char *argv[])
{
	int run_bootstrap = 0;

	//Run getopt if arguments passed to bpfgen
	if (argc >= 2) {
		int opt;
		while ((opt = getopt(argc, argv, "t")) != -1) {
			switch(opt){
				case 't':
					fprintf(stdout, "Running bootstrap\n");
					run_bootstrap = 1;
					break;
				default:
					fprintf(stderr, "Not sure what you're looking for there, sir\n");
					break;
			}
		}
	}

	//HERE: logging

	//Main function to translate and load bpf program
	int ret; // return code
	ret = sdwan2bpf(run_bootstrap);

	//free memory
	//fclose (log_file);

	return ret;
}
