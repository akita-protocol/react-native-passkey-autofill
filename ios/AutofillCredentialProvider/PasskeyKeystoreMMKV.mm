#import "PasskeyKeystoreMMKV.h"

#import <MMKVCore/MMKV.h>

#ifdef MMKV_APPLE
using PasskeyMMKV = mmkv::MMKV;
static constexpr auto PasskeyMMKVMultiProcess = mmkv::MMKV_MULTI_PROCESS;
#else
using PasskeyMMKV = MMKV;
static constexpr auto PasskeyMMKVMultiProcess = MMKV_MULTI_PROCESS;
#endif

@implementation PasskeyKeystoreMMKV

+ (nullable PasskeyMMKV *)keystoreForAppGroup:(NSString *)appGroup
                                        error:(NSError * _Nullable * _Nullable)error {
  NSURL *containerURL = [[NSFileManager defaultManager]
    containerURLForSecurityApplicationGroupIdentifier:appGroup];
  if (containerURL == nil) {
    if (error != nil) {
      *error = [NSError errorWithDomain:@"ReactNativePasskeyAutofill"
                                   code:2
                               userInfo:@{
                                 NSLocalizedDescriptionKey:
                                   [NSString stringWithFormat:@"App Group is not accessible: %@", appGroup]
                               }];
    }
    return nil;
  }

  std::string rootPath([containerURL.path UTF8String]);
  PasskeyMMKV::initializeMMKV(rootPath);
  return PasskeyMMKV::mmkvWithID("keystore", PasskeyMMKVMultiProcess, nullptr, &rootPath);
}

+ (BOOL)setString:(NSString *)value
           forKey:(NSString *)key
         appGroup:(NSString *)appGroup
            error:(NSError * _Nullable * _Nullable)error {
  PasskeyMMKV *keystore = [self keystoreForAppGroup:appGroup error:error];
  if (keystore == nullptr) {
    return NO;
  }

#ifdef MMKV_APPLE
  return keystore->set([value UTF8String], key);
#else
  std::string cppValue([value UTF8String]);
  std::string cppKey([key UTF8String]);
  return keystore->set(cppValue, cppKey);
#endif
}

+ (nullable NSString *)stringForKey:(NSString *)key
                           appGroup:(NSString *)appGroup
                              error:(NSError * _Nullable * _Nullable)error {
  PasskeyMMKV *keystore = [self keystoreForAppGroup:appGroup error:error];
  if (keystore == nullptr) {
    return nil;
  }

#ifdef MMKV_APPLE
  std::string result = keystore->getString(key);
  if (result.empty()) {
    return nil;
  }
#else
  std::string result;
  std::string cppKey([key UTF8String]);
  if (!keystore->getString(cppKey, result)) {
    return nil;
  }
#endif
  return [NSString stringWithUTF8String:result.c_str()];
}

+ (NSArray<NSString *> *)allKeysForAppGroup:(NSString *)appGroup
                                      error:(NSError * _Nullable * _Nullable)error {
  PasskeyMMKV *keystore = [self keystoreForAppGroup:appGroup error:error];
  if (keystore == nullptr) {
    return @[];
  }

#ifdef MMKV_APPLE
  NSArray *keys = keystore->allKeysObjC();
  NSMutableArray<NSString *> *result = [NSMutableArray arrayWithCapacity:keys.count];
  for (id key in keys) {
    if ([key isKindOfClass:[NSString class]]) {
      [result addObject:(NSString *)key];
    }
  }
#else
  std::vector<std::string> keys = keystore->allKeys();
  NSMutableArray<NSString *> *result = [NSMutableArray arrayWithCapacity:keys.size()];
  for (const auto &key : keys) {
    [result addObject:[NSString stringWithUTF8String:key.c_str()]];
  }
#endif
  return result;
}

+ (BOOL)removeValueForKey:(NSString *)key
                 appGroup:(NSString *)appGroup
                    error:(NSError * _Nullable * _Nullable)error {
  PasskeyMMKV *keystore = [self keystoreForAppGroup:appGroup error:error];
  if (keystore == nullptr) {
    return NO;
  }

#ifdef MMKV_APPLE
  keystore->removeValueForKey(key);
#else
  std::string cppKey([key UTF8String]);
  keystore->removeValueForKey(cppKey);
#endif
  return YES;
}

@end
