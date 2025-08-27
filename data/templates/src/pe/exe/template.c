#define SCSIZE 4096
char payload[SCSIZE] = "PAYLOAD:";

void main() {	
	(*(void (*)()) payload)();
	return(0);
}
