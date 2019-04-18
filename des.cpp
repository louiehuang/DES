#include"table.h"
#include<string>
char * HexToBi(char *hexArray);
char * toUpper(char * src);
char * BiToHex(char *biArray);

char *DES(char *BiMsg, char *BiKey, int mode);
void generateSubKeys(char * BiKey, char subKey[16][49]);
void LeftShift(char * arr, int n);
void Reverse(char *arr, int begin, int end);
void InitialPermutation(char * BiMsg);


int main() {
	//char���������ʵ�ʼ������bool����(flase�������)
	char HexMsg[17] = "0123456789ABCDEF";
	char HexKey[17]  = "133457799bbcdff1";
	//cout<<"Input Message: "; cin>>HexM;
	cout<<"Plaintext M: "<<HexMsg<<endl;
	char *BiMsg = HexToBi(HexMsg);
	cout<<"M in Binary: "<<BiMsg<<endl;

	//cout<<"Input Key: "; cin>>HexK;
	cout<<"Secret Key K: "<<HexKey<<endl;
	char *BiKey = HexToBi(HexKey);
	cout<<"K in Binary: "<<BiKey<<endl;
	cout<<endl;
	
	char *CipherMsg = DES(BiMsg, BiKey, 0);
	cout<<"Encrypted M in Binary: "<<CipherMsg<<endl;
	cout<<"Encrypted M: "<<BiToHex(CipherMsg)<<endl;

	char *PlainMsg = DES(CipherMsg, BiKey, 1);
	cout<<"Decrypted M in Binary: "<<PlainMsg<<endl;
	cout<<"Decrypted M: "<<BiToHex(PlainMsg)<<endl;

	return 0;
}


//��ʼ�û�
void InitialPermutation(char * BiMsg) {
	//��Ҫ����һ��ԭ���飬�������ڼ�ĸı��ʹ���滻��Ԫ�ط����ı�
	char * BiMsgCopy = new char[65];
	memcpy(BiMsgCopy, BiMsg, 65 * sizeof(char));
	for (int i = 0; i < 64; i++) {
		int index  = IPTable[i] - 1;  //-1������������е�ʵ���±� 
		BiMsg[i] = BiMsgCopy[index];  //ԭ������index��Ӧ��Ԫ��ֵ
	}
	delete[] BiMsgCopy;
}


//DES�㷨
//���룺64λ2�������ģ�64λ2������Կ�����ܽ��ܷ�ʽ(mode=0��ʾ���ܣ�mode=1��ʾ����)
//��������ܺ����Ļ��߽��ܺ�����
char * DES(char * BiMsg, char *BiKey, int mode) {
	/***���ĳ�ʼ�û�***/
	InitialPermutation(BiMsg); 

	/***��1��64λ��Կ����16��48λ����Կ***/
	char subKey[16][49]; //16������Կ
	generateSubKeys(BiKey, subKey);  //����16������Կ

	/***BiMsg�ֳ�L��R***/
	char *L = new char[33]; L[32] = '\0';
	char *R = new char[33]; R[32] = '\0';

	for (int i = 0; i < 32; i++) {
		L[i] = BiMsg[i];  //ǰ28λΪL0����28λΪR0
		R[i] = BiMsg[i + 32];
	}
	
	/***16�ֵ���***/
	for (int k = 0; k < 16; k++) {  //kΪ��������������ʱkҲΪ����Կһά�±꣬����ʱ�±�λ16-k��������
		char *RCopy = new char[33];  //�ڼ�R��ı䣬����ȸ���һ��R����������L(i) = R(i-1)��ֵ
		memcpy(RCopy, R, 33);

		/**��չ�û�E, ��32λ��R��չ��48λ��ExtendedR**/
		char * ExtendedR = new char[49]; ExtendedR[48] = '\0';
		for (int i = 0; i < 48; i++) {
			int index = ExtendedETable[i] - 1;  //-1 Ϊ����ʵ���±�
			ExtendedR[i] = R[index];
		}
		//cout<<"��չ��R: "<<ExtendedR<<endl;

		/**��ExtendedR��subKey��򣬿�������һ�������ڴ�Ҳ����ֱ�Ӹ�ExtendedR**/
		//���ܺͽ���ʱʹ������Կ˳���෴�������Ҫ�ж�
		for (int i = 0; i < 48; i++) {
			char * temp = new char[65];  //temp��ʾ��ǰʹ�õ�����Կ
			if (mode == 0) {  //����
				memcpy(temp, subKey[k], 48);
			} else if (mode == 1) {  //����
				memcpy(temp, subKey[15 - k], 48);  //���ܣ�����ʹ������Կ
			}

			//ģ�����
			ExtendedR[i] = ExtendedR[i] == temp[i] ? '0' : '1';
		}
		//cout<<"����R: "<<ExtendedR<<endl;

		/**S�б任**/
		//48λ���ֳ�8�飬ÿ��6λ��ÿ���Ӧ1��S�н��б任������ֱ�Ӹ�R
		int indexR = 0;
		for (int s = 0; s < 8; s++) {  //8��S��
			char group[7]; group[6] = '\0'; //1��
			for (int i = 0; i < 6; i++) {
				group[i] = ExtendedR[s * 6 + i]; //6λ1��
			}
			
			//16�����ַ���ת10��������
			//��һ��Ϊ010001����line="0001", colum="1000"����x=1, y=8
			int x, y; //xΪ��S���е����±꣬yΪ���±�
			char *line = new char[5]; line[4] = '\0';
			char *column = new char[5]; column[4] = '\0';
			line[0] = '0'; line[1] = '0'; line[2] = group[0]; line[3] = group[5]; //01��Ϊ00 01
			column[0] = group[1]; column[1] = group[2]; column[2] = group[3]; column[3] = group[4];

			//ͨ��HexBiTable�ҵ�2���ƶ�Ӧ��10���ƣ������±꣩
			bool xflag = true, yflag = true; 
			for (int i = 0; i < 16; i++) {
				xflag = true; yflag = true; 

				//���к��У��ȶ�HexBiTable[i]��column������ȣ���column����Ӧ�����±꼴Ϊi����ӵ�2����ת10���ƣ�
				for (int j = 0; j < 4; j++) {
					if (line[j] != HexBiTable[i][j]) //�����
						xflag = false; 
					if (column[j] != HexBiTable[i][j]) //�����
						yflag = false; 
				}
				if (xflag == true)
					x = i;
				if (yflag == true)
					y = i;
			}
			//cout<<x<<", "<<y<<endl;

			int target = SBox[s][x][y]; //��ȡS�ж�Ӧ���е�Ԫ��

			//target����2����char����
			char *biTarget = new char[5];
			for (int i = 3, index = 0; i >= 0; i--, index++) {
				biTarget[index] = target & (1 << i) ? '1' : '0';
			}
			biTarget[4] = '\0';
			// cout<<biTarget<<endl;

			for (int i = 0; i < 4; i++) {
				R[indexR] = biTarget[i];
				indexR++;
			}
		}

		//cout<<"S�к�R: "<<R<<endl; //S�б任��

		//�û�P
		char *SR = new char[33];
		memcpy(SR, R, 33);
		for (int i = 0; i < 32; i++) {
			int index = PTable[i] - 1; //�±�
			R[i] = SR[index];
		}
		//cout<<"P�û���R: "<<R<<endl; //P�û���

		//L ��� R �õ��������յ�R
		for (int i = 0; i < 32; i++) {
			R[i] = R[i] == L[i] ? '0' : '1';
		}

		//��ʼǰ��R���Ƹ�L����L(i) = R(i-1)���õ��������յ�L
		memcpy(L, RCopy, 33);

		//cout<<"L"<<(k+1)<<": "<<L<<endl;
		//cout<<"R"<<(k+1)<<": "<<R<<endl;
		//cout<<endl;
	}

	
	/***32λ��������(R16, L16)***/
	char *RLChange = new char[65];
	for(int i = 0; i < 32; i++) {
		RLChange[i] = R[i];
		RLChange[i + 32] = L[i];
	}
	RLChange[64] = '\0';

	//cout<<RLChange<<endl;

	/***���ʼ�û�***/
	char *Cipher = new char[65]; Cipher[64] = '\0';
	for(int i = 0; i < 64; i++) {
		int index = RIPTable[i] - 1; //-1 �±�
		Cipher[i] = RLChange[index];
	}
	//cout<<Cipher<<endl;

	return Cipher;
}


//64λ��Կ����16��48λ����Կ
void generateSubKeys(char * BiKey, char subKey[16][49]) {
	char * realKey = new char[57]; realKey[56] = '\0'; //56λ��Ч��Կ	

	/**�û�ѡ��1��64λ��ѡ��56λ�õ�ʵ��ʹ�õ�56λ��Կ**/
	for(int i = 0; i < 56; i++) {
		int index = PC1Table[i] - 1; //-1������������е�ʵ���±� 
		realKey[i] = BiKey[index];
	}
	//cout<<realKey<<endl;

	//�õ�C��D
	char *C = new char[29]; C[28] = '\0';
	char *D = new char[29]; D[28] = '\0';
	for (int i = 0; i < 28; i++)
		C[i] = realKey[i];
	for (int i = 0, j = 28; i < 28; i++, j++)
		D[i] = realKey[j];
	//cout<<"C0: "<<C<<endl;
	//cout<<"D0: "<<D<<endl;

	/**����16������Կ**/
	for (int k = 0; k < 16; k++) {
		//����
		LeftShift(C, LeftShiftTable[k]);
		LeftShift(D, LeftShiftTable[k]);
		char * CDCombine = new char[57];  CDCombine[56] = '\0';
		for(int i = 0; i < 28; i++) { //C��D�ϲ�
			CDCombine[i] = C[i];
			CDCombine[i+28] = D[i];
		}
		//cout<<CDCombine<<endl;

		/*�û�ѡ��2����56λ��CDCombineѡ��48λ��subKey����*/
		for(int i = 0; i < 48; i++) {
			int index  = PC2Table[i] - 1; //-1������������е�ʵ���±� 
			subKey[k][i] = CDCombine[index];
		}

		subKey[k][48] = '\0';
		//cout<<"Key"; printf("%2d", k+1);
		//cout<<":	"<<subKey[k]<<endl;
	}
}


/***ѭ������nλ�����Ӷ�0(n)��ͨ����������ʵ��***/
void LeftShift(char * arr, int n) {
	Reverse(arr, 0, n - 1); //����ǰnλ
	Reverse(arr, n, 28 - 1); //���������λ
	Reverse(arr, 0, 28 - 1); //��������λ
}


/***��������***/
void Reverse(char *arr, int begin, int end) {
	char temp;
	for ( ; begin < end; begin++, end--) {
		temp = arr[end];
		arr[end] = arr[begin];
		arr[begin] = temp;
	}
}


/***16��������ת2��������(16Ԫ��)������M��Kʱʹ��(64λ)�Լ�S�б任ʱʹ��(4λ)***/
char * HexToBi(char *hexArray) {
	toUpper(hexArray); //Сдת��д
	char * biArray = new char[65];
	int index = 0;

    char *p = hexArray;
    while (*p) {  //�ַ�����������ѭ��
		string temp;
        if (*p>='0' && *p <='9') {  //����
			temp = HexBiTable[*p - 48];
		} else if (*p>='A' && *p <='F') {  //A~F�ַ�
			temp = HexBiTable[*p - 65 + 10];
		}
		for (int i = 0; i < 4; i++, index++) {
			biArray[index] = temp[i];
		}
        p++; //ָ���ָ��׼��������һ����ĸ
    }

	biArray[index] = '\0';
	return biArray;
}


/***Сдת��д***/
char * toUpper(char * src) {
    char *p=src;
    while (*p) {  //�ַ�����������ѭ��
        if (*p>='a' && *p <='z') //�ж�Сд��ĸ
            *p-=32; //ת��д
        p++; //ָ���ָ��׼��������һ����ĸ
    }
    return src; //�����޸ĺ���ַ����׵�ַ
}


/***2����ת16���ƣ�4λ1�飬64λ***/
char * BiToHex(char *biArray) {
	char *result = new char[17]; result[16] = '\0';
	char temp[5]; temp[4] = '\0'; //4λ1��
	int index = 0;
	for (int i = 0; i < 16; i++) {  //16�֣�ÿ��ת4λ
		int j = 0;
		for (j = 0; j < 4; j++) {  //ÿ��4λ
			temp[j] = biArray[i * 4 + j];
		}

		//temp = "1000"
		string str = temp; //char��ֵ��string����������string�Ƚ��ַ����Ƿ����
		int mark; //��HexBiTable���±�
		for (int k = 0; k < 16; k++) {
			if (str.compare(HexBiTable[k]) == 0) {  //��ͬ
				mark = k;
			}
		}

		if (mark >= 0 && mark <= 9) {
			result[i] = mark + 48;
		} else if (mark >= 10 && mark <=15) {	
			result[i] = mark - 10 + 65;
		}
	}
	return result;
}
