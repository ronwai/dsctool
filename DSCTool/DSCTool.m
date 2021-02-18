//
//  DSCTool.m
//

#import "DSCTool.h"
#import "objc/runtime.h"


@interface DSCTool ()

@property(strong, nonatomic, nonnull) NSObject<HPHopperServices> *services;
@property(strong, nonatomic, nonnull) NSObject<HPDocument> *document;
@property(strong, nonatomic, nonnull) NSObject<HPDisassembledFile> *file;

- (Address)dePACAndImportAddress:(Address)addr :(Address)dest;
- (Address)analyzeAddressAsObjcClass:(Address)addr;
- (void)analyzeCurrentAddressAsObjcClass:(id)sender;
- (void)commentCurrentAddressAsObjcClass:(id)sender;

@end


@implementation DSCTool

- (instancetype)initWithHopperServices:(NSObject<HPHopperServices> *)services {
  if (self = [super init]) {
    _services = services;
    _document = [self.services currentDocument];
    _file = [self.document disassembledFile];
  }

  return self;
}

+ (int)sdkVersion {
    return HOPPER_CURRENT_SDK_VERSION;
}

- (NSArray *)toolMenuDescription {
    return @[@{
      HPM_TITLE : @"Analyze current address as __objc_class",
      HPM_SELECTOR : NSStringFromSelector(@selector(analyzeCurrentAddressAsObjcClass:))
    }, @{
      HPM_TITLE : @"Comment current address as runtime class",
      HPM_SELECTOR : NSStringFromSelector(@selector(commentCurrentAddressAsObjcClass:))
    }, @{
      HPM_TITLE : @"mark undefined",
      HPM_SELECTOR : NSStringFromSelector(@selector(markUndefined:))
    }, @{
      HPM_TITLE : @"comment",
      HPM_SELECTOR : NSStringFromSelector(@selector(comment:))
    }, @{
     HPM_TITLE : @"shift",
     HPM_SELECTOR : NSStringFromSelector(@selector(shiftAddresses:))
    }];
}

- (nonnull NSObject<HPHopperUUID> *)pluginUUID {
    return [self.services UUIDWithString:@"b31e43f4-e2b8-4202-9452-841131d16d39"];
}

- (HopperPluginType)pluginType {
    return Plugin_Tool;
}

- (nonnull NSString *)pluginName {
    return @"DSCTool";
}

- (nonnull NSString *)pluginDescription {
    return @"Auto-analyze addresses in the dyld_shared_cache";
}

- (nonnull NSString *)pluginAuthor {
    return @"@epsilan";
}

- (nonnull NSString *)pluginCopyright {
    return @"whatever";
}

- (nonnull NSString *)pluginVersion {
    return @"1.0.0";
}

/// Returns a string identifying the plugin for the command line tool.
/// For instance, the Mach-O loader returns "Mach-O".
/// You should avoid spaces in order to avoid quotes in the command line.
- (nonnull NSArray<NSString *> *)commandLineIdentifiers {
    return @[@"dsctool"];
}

/// Idempotent method that will dePAC and import |addr|, even if not pointer authenticated and/or already imported.
/// The result is written to |dest| to overwrite the previously authenticated address.
- (Address)dePACAndImportAddress:(Address)addr :(Address)dest {
    [self.document dePACAddress:addr storedAt:dest];
    Address dePACedAddress = [self.document readAddressAtVirtualAddress:dest];
    [self.document logInfoMessage:[NSString stringWithFormat:@"addr: %llx, dest: %llx, dePAC: %llx", addr, dest, dePACedAddress ]];
    BOOL ok = [self.document importAddressFromDYLDCache:dePACedAddress];
    if (!ok) {
        [self.document logErrorStringMessage:[NSString stringWithFormat:@"Error importing address: %llx", addr]];
        return 0;
    }
    [self.document logStringMessage:[NSString stringWithFormat:@"Successful dePAC and import of %llx", addr]];
    return dePACedAddress;
}

/// Similar version of above method but address is returned instead of written
- (Address)dePACAndImportAddress:(Address)addr {
    Address dePACedAddress = [self.file dePACAddress:addr];
    BOOL ok = [self.document importAddressFromDYLDCache:dePACedAddress];
    if (!ok) {
        [self.document logErrorStringMessage:[NSString stringWithFormat:@"Error importing address: %llx", addr]];
        return 0;
    }
    return dePACedAddress;
}

- (Address)pointerForTypeOffset:(Address)addr fieldName:(NSString *)field {
    NSObject<HPSegment> *seg = [self.file segmentForVirtualAddress:addr];
    NSObject<HPTypeDesc> *typeDesc = [seg structureTypeAt:addr];
    if (typeDesc == nil) {
        return 0;
    }
    Address offset = [typeDesc offsetForStructureFieldPathString:field];
    return addr + offset;
}

- (Address)dePACAndImportField:(Address)addr fieldName:(NSString *)field {
    Address ptr = [self pointerForTypeOffset:addr fieldName:field];
    Address value = [self.document readAddressAtVirtualAddress:ptr];
    return [self dePACAndImportAddress:value:ptr];
}

- (Address)analyzeAddressAsObjcClass:(Address)addr isMeta:(BOOL)meta {
    // 1. read, dePAC, and import address from DSC
    Address objcClassAddr = [self.document readAddressAtVirtualAddress:addr];
    Address objcClassAddrDePAC = [self dePACAndImportAddress:objcClassAddr:addr];
    if (objcClassAddrDePAC == 0) {
        return 0;
    }
    // 2. read address and define it as __objc_class
    NSObject<HPTypeDesc> *objcClassTypeDesc = [self.file typeWithName:@"__objc_class"];
    [self.file defineStructure:objcClassTypeDesc at:objcClassAddrDePAC];
    if ([self.file hasStructureDefinedAt:objcClassAddrDePAC]) {
        [self.document logStringMessage:[NSString stringWithFormat:@"Successfully defined objc_class at %llx", objcClassAddrDePAC]];
    } else {
        [self.document logErrorStringMessage:[NSString stringWithFormat:@"Error defining objc_class at %llx", objcClassAddrDePAC]];
        return 0;
    }
    // 3. dePAC, import then define objc_data
    Address objcDataAddrDePAC = [self dePACAndImportField:objcClassAddrDePAC fieldName:@"data"];
    if (objcDataAddrDePAC == 0) {
        return 0;
    }
    NSObject<HPTypeDesc> *objcDataType = [self.file typeWithName:@"__objc_data"];
    [self.file defineStructure:objcDataType at:objcDataAddrDePAC];
    
    // 5. dePAC, import, read, and set class name
    Address objcClassNameAddrDePAC = [self dePACAndImportField:objcDataAddrDePAC fieldName:@"name"];
    NSString *className = [self.document readCStringAt:objcClassNameAddrDePAC];
    [self.document logStringMessage:[NSString stringWithFormat:@"Found class: %@", className]];
    NSObject<HPSegment> *seg = [self.file segmentForVirtualAddress:objcClassNameAddrDePAC];
    [seg makeASCIIAt:objcClassNameAddrDePAC];
    
    // 6. dePAC & import baseMethods
    Address baseMethods = [self dePACAndImportField:objcDataAddrDePAC fieldName:@"baseMethods"];
    if (baseMethods != 0) {
        [self analyzeBaseMethods:baseMethods];
    }
    
    // 7. ... ivars
    Address ivars = [self dePACAndImportField:objcDataAddrDePAC fieldName:@"ivars"];
    if (ivars != 0) {
        [self analyzeIvars:ivars];
    }
    
    // 8. ... baseProperties
    Address baseProperties = [self dePACAndImportField:objcDataAddrDePAC fieldName:@"baseProperties"];
    if (baseProperties != 0) {
        [self analyzeProperties:baseProperties];
    }
    
    // 9. handle protocols with -(void)commentNewRuntimeProtocolAt:(unsigned long long)arg2
    Address protocols = [self dePACAndImportField:objcDataAddrDePAC fieldName:@"baseProtocols"];
    if (protocols != 0) {
        [self analyzeProtocols:protocols];
    }
    
    return objcClassAddrDePAC;
}

- (void)analyzeBaseMethods:(Address)addr {
    NSObject<HPTypeDesc> *methodList = [self.file typeWithName:@"__objc_method_list"];
    [self.file defineStructure:methodList at:addr];
    Address count = [self.file readUnsignedValueForFieldPath:@"count" at:addr];
    BOOL relative = [self.file readUnsignedValueForFieldPath:@"flags" at:addr];
    
    NSObject<HPTypeDesc> *methodType;
    if (relative) {
        methodType = [self.file typeWithName:@"__objc_relative_method"];
    } else {
        methodType = [self.file typeWithName:@"__objc_method"];
    }
    
    NSString *name;
    Address curMethod = addr + [methodList sizeOf];
    for (int i = 0; i < count; i++) {
        [self.file defineStructure:methodType at:curMethod];
        if (relative) {
            int32_t nameOffset = (int32_t)[self.file readUnsignedValueForFieldPath:@"name" at:curMethod];
            if ([self.file hasMappedDataAt:curMethod + nameOffset]) {
                name = [self.file readCStringAt:curMethod + nameOffset];
            } else {
                Address nameAddr = [self dePACAndImportAddress:curMethod + nameOffset];
                name = [self.file readCStringAt:nameAddr];
            }
        } else {
            Address nameAddr = [self.file readUnsignedValueForFieldPath:@"name" at:curMethod];
            Address nameDePAC = [self dePACAndImportAddress:nameAddr :curMethod];
            name = [self.file readCStringAt:nameDePAC];
        }
        [self.file setComment:name atVirtualAddress:curMethod reason:CCReason_User];
        curMethod += [methodType sizeOf];
    }
}

- (void)analyzeIvars:(Address)addr {
    NSObject<HPTypeDesc> *ivar = [self.file typeWithName:@"__objc_ivar"];
    NSObject<HPTypeDesc> *ivars = [self.file typeWithName:@"__objc_ivars"];
    [self.file defineStructure:ivars at:addr];
    Address count = [self.file readUnsignedValueForFieldPath:@"count" at:addr];
    
    NSString *name;
    Address curIvar = addr + [ivars sizeOf];
    for (int i = 0; i < count; i++) {
        [self.file defineStructure:ivar at:curIvar];
        // dePAC & read offset pointer (at an offset of 0x0 from curIvar)
        Address offsetPtr = [self dePACAndImportField:curIvar fieldName:@"offset"];
        uint32_t offset = [self.file readUInt32AtVirtualAddress:offsetPtr];
        // dePAC & read name
        Address namePtr = [self dePACAndImportField:curIvar fieldName:@"name"];
        name = [self.file readCStringAt:namePtr];
        // comment name & offset
        [self.file setComment:[NSString stringWithFormat:@"name: %@ offset: %#x", name, offset] atVirtualAddress:curIvar reason:CCReason_User];
        curIvar += [ivar sizeOf];
    }
}

- (void)analyzeProperties:(Address)addr {
    NSObject<HPTypeDesc> *property = [self.file typeWithName:@"__objc_property"];
    NSObject<HPTypeDesc> *propertyList = [self.file typeWithName:@"__objc_property_list"];
    [self.file defineStructure:propertyList at:addr];
    Address count = [self.file readUnsignedValueForFieldPath:@"count" at:addr];
    
    NSObject<HPSegment> *seg;
    Address curProperty = addr + [propertyList sizeOf];
    for (int i = 0; i < count; i++) {
        [self.file defineStructure:property at:curProperty];
        // dePAC & import name
        Address namePtr = [self dePACAndImportField:curProperty fieldName:@"name"];
        //Address nameAddr = [self.file readVir];
        seg = [self.file segmentForVirtualAddress:namePtr];
        [seg makeASCIIAt:namePtr];
        curProperty += [property sizeOf];
    }
}

- (void)analyzeProtocols:(Address)addr {
    NSObject<HPTypeDesc> *protocol = [self.file typeWithName:@"__objc_protocol"];
    NSObject<HPTypeDesc> *protocolExt = [self.file typeWithName:@"__objc_protocol_ext"];
    NSObject<HPTypeDesc> *protocolList = [self.file typeWithName:@"__objc_protocol_list"];
    [self.file defineStructure:protocolList at:addr];
    Address count = [self.file readUnsignedValueForFieldPath:@"count" at:addr];
    // define, dePAC, import, and analyze each protocol
    Address curProtocolPtr = addr + sizeof(void *);
    for (int i = 0; i < count; i++) {
        Address curProtocol = [self.file readAddressAtVirtualAddress:curProtocolPtr];
        Address dePACedProtocol = [self dePACAndImportAddress:curProtocol :curProtocolPtr];
        BOOL ext = [self.file isExtendedProtocolAt:addr];
        if (ext) {
            [self.file defineStructure:protocolExt at:dePACedProtocol];
        } else {
            [self.file defineStructure:protocol at:dePACedProtocol];
        }
        // name
        Address nameAddr = [self dePACAndImportField:dePACedProtocol fieldName:@"name"];
        NSString *name = [self.document readCStringAt:nameAddr];
        [self.document logStringMessage:[NSString stringWithFormat:@"Found protocol: %@", name]];
        NSObject<HPSegment> *seg = [self.file segmentForVirtualAddress:nameAddr];
        [seg makeASCIIAt:nameAddr];
        // protocols
        // instance methods
        // class methods
        // optional instance methods
        // optional class methods
        // optional extended method types, can we demangle & comment type info? maybe with class-dump's formatType
        curProtocolPtr += sizeof(void *);
    }
}

- (void)analyzeCurrentAddressAsObjcClass:(id)sender {
    _document = [self.services currentDocument];
    _file = [self.document disassembledFile];
    [self analyzeAddressAsObjcClass:[self.document currentAddress]];
}

- (void)markUndefined:(id)sender {
    _document = [self.services currentDocument];
    _file = [self.document disassembledFile];
}

- (void)comment:(id)sender {
    _document = [self.services currentDocument];
    _file = [self.document disassembledFile];
    Address maybePAC = [self.document readAddressAtVirtualAddress:[self.document currentAddress]];
    Address dePACedAddress = [self.file dePACAddress:maybePAC];
    BOOL ok = [self.document importAddressFromDYLDCache:dePACedAddress];
    if (!ok) {
        [self.document logErrorStringMessage:[NSString stringWithFormat:@"Error importing address:"]];
    }
    [self.document logInfoMessage:[NSString stringWithFormat:@"dePAC + import: %#llx, maybePAC: %#llx", dePACedAddress, maybePAC]];
}

- (void)shiftAddresses:(id)sender {
    _document = [self.services currentDocument];
    [self.document popNavigationStackToIndex:0x1];
}

- (void)commentCurrentAddressAsObjcClass:(id)sender {
    _document = [self.services currentDocument];
    _file = [self.document disassembledFile];
    Address stackPtrBefore = [self.document navigationStackPointer];
    
    [self.document beginToWait:@"Please standby..."];
    
    // analyze current addr as objc_class
    Address addr = [self.document currentAddress];
    Address objcClassAddr = [self analyzeAddressAsObjcClass:addr isMeta:false];
    if (objcClassAddr == 0) {
        return;
    }
    [self.document logStringMessage:[NSString stringWithFormat:@"objcClassAddr: %#llx", objcClassAddr]];
    // analyze metaclass
    Address metaclassPtr = [self pointerForTypeOffset:objcClassAddr fieldName:@"metaclass"];
    if (metaclassPtr == 0) {
        return;
    }
    [self.document logStringMessage:[NSString stringWithFormat:@"metaclassPtr: %#llx", metaclassPtr]];
    [self analyzeAddressAsObjcClass:metaclassPtr isMeta:true];
    
    // analyze superclass
    Address superclassPtr = [self pointerForTypeOffset:objcClassAddr fieldName:@"superclass"];
    if (superclassPtr == 0) {
        return;
    }
    [self.document logStringMessage:[NSString stringWithFormat:@"superclassPtr: %#llx", superclassPtr]];
    [self analyzeAddressAsObjcClass:superclassPtr isMeta:false];
    
    // reset navigation stack to before
    [self.document popNavigationStackToIndex:stackPtrBefore];
    
    // hack: undefine the class because |commentNewRuntimeClassAt| checks to make sure it's not defined...
    [self.document logStringMessage:[NSString stringWithFormat:@"undefining: %#llx", objcClassAddr]];
    [self.file setType:Type_Undefined atVirtualAddress:objcClassAddr forLength:1];
    
    // now we let Hopper do its magic
    [self.document logStringMessage:[NSString stringWithFormat:@"commenting: %#llx", objcClassAddr]];
    [self.file removeCommentAtVirtualAddress:objcClassAddr];
    [self.file commentNewRuntimeClassAt:objcClassAddr];

    [self.document updateUI];
    [self.document waitForBackgroundProcessToEnd];
    [self.document endWaiting];
}

@end
