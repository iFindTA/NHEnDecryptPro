//
//  ViewController.m
//  NHEnDecryptPro
//
//  Created by hu jiaju on 15/9/15.
//  Copyright (c) 2015年 hu jiaju. All rights reserved.
//

#import "ViewController.h"
#import "NHCryptor.h"

@interface ViewController ()

@property (nonatomic, strong)UITextField *textFD;
@property (nonatomic, strong)UILabel *scoreLabel,*aesLabel,*rsaLabel;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    CGRect infoRect = CGRectMake(50, 100, 200, 30);
    UITextField *textfd = [[UITextField alloc] initWithFrame:infoRect];
    textfd.keyboardType = UIKeyboardTypeNamePhonePad;
    textfd.placeholder = @"输入要加密的内容";
    [self.view addSubview:textfd];
    _textFD = textfd;
    
    infoRect.origin.y += 40;
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeCustom];
    btn.frame = infoRect;
    [btn setTitle:@"密码 得分" forState:UIControlStateNormal];
    [btn setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
    [btn addTarget:self action:@selector(scoreEvent) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:btn];
    infoRect.origin.y += 40;
    _scoreLabel = [[UILabel alloc] initWithFrame:infoRect];
    [self.view addSubview:_scoreLabel];
    
    infoRect.origin.y += 40;
    btn = [UIButton buttonWithType:UIButtonTypeCustom];
    btn.frame = infoRect;
    [btn setTitle:@"AES 加密" forState:UIControlStateNormal];
    [btn setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
    [btn addTarget:self action:@selector(aesEncrypt) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:btn];
    infoRect.origin.y += 40;
    _aesLabel = [[UILabel alloc] initWithFrame:infoRect];
    [self.view addSubview:_aesLabel];
    
    infoRect.origin.y += 40;
    btn = [UIButton buttonWithType:UIButtonTypeCustom];
    btn.frame = infoRect;
    [btn setTitle:@"RSA 加密" forState:UIControlStateNormal];
    [btn setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
    [btn addTarget:self action:@selector(rsaEncrypt) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:btn];
    infoRect.origin.y += 40;
    _rsaLabel = [[UILabel alloc] initWithFrame:infoRect];
    [self.view addSubview:_rsaLabel];
}

- (void)touchesBegan:(NSSet *)touches withEvent:(UIEvent *)event{
    [self.view endEditing:true];
}

- (void)scoreEvent {
    NSString *info = _textFD.text;
    if (info.length <= 0) {
        return;
    }
    int score = NHSSLKit->score_passphrase([info UTF8String]);
    _scoreLabel.text = [NSString stringWithFormat:@"密码强度得分: %d",score];
}

- (void)aesEncrypt{
    
    NSString *info = _textFD.text;
    if (info.length <= 0) {
        return;
    }
    NSString *aeskey = NHSSLKit->aesGenerateKey();
    NSString *aesRet = NHSSLKit->aesEncrypt(info,aeskey);
    _aesLabel.text = aesRet;
}

- (void)rsaEncrypt{
    NSString *info = _textFD.text;
    if (info.length <= 0) {
        return;
    }
    NSString *rsaRet = NHSSLKit->rsaEncrypt(info);
    _rsaLabel.text = rsaRet;
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
