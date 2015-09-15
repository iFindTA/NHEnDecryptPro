//
//  ViewController.m
//  NHEnDecryptPro
//
//  Created by hu jiaju on 15/9/15.
//  Copyright (c) 2015年 hu jiaju. All rights reserved.
//

#import "ViewController.h"
#import "NHSSLCImpPro.h"

@interface ViewController ()

@property (nonatomic, strong)UITextField *textFD;
@property (nonatomic, strong)UILabel *aesLabel,*rsaLabel;

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

- (void)aesEncrypt{
    
    NSString *info = _textFD.text;
    if (info.length <= 0) {
        return;
    }
    NSString *aeskey = NHSSLUtil->aesGenerateKey();
    NSString *aesRet = NHSSLUtil->aesEncrypt(info,aeskey);
    _aesLabel.text = aesRet;
}

- (void)rsaEncrypt{
    NSString *info = _textFD.text;
    if (info.length <= 0) {
        return;
    }
    NSString *rsaRet = NHSSLUtil->rsaEncrypt(info);
    _rsaLabel.text = rsaRet;
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
