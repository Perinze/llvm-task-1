#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/TargetTransformInfo.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

#include "llvm/Analysis/AliasAnalysis.h"

#define DEBUG_TYPE "memory-safety"

using namespace llvm;

namespace {
    struct MemorySafetyPass : PassInfoMixin<MemorySafetyPass> {
    public:
        bool transformMalloc(CallInst &CI) {
            if (CI.getCalledFunction()->getName() != "malloc") {
                errs() << "Called function is not malloc\n";
                return false;
            }
            CI.getCalledFunction()->setName("__runtime_malloc");
            errs() << "Transformed to __runtime_malloc\n";
            return true;
        }

        bool transformFree(CallInst &CI) {
            if (CI.getCalledFunction()->getName() != "free") {
                errs() << "Called function is not free\n";
                return false;
            }
            CI.getCalledFunction()->setName("__runtime_free");
            errs() << "Transformed to __runtime_free\n";
            return true;
        }

        void addInit(Function &F) {
            LLVMContext &C = F.getContext();
            FunctionCallee func = F.getParent()->getOrInsertFunction(
                    "__runtime_init", Type::getVoidTy(C));

            auto BB = &(*F.begin());
            auto I = &(*BB->begin());
            IRBuilder<> builder(I);
            builder.SetInsertPoint(I);
            builder.CreateCall(func);
        }

        void addClean(Function &F) {
            LLVMContext &C = F.getContext();
            FunctionCallee func = F.getParent()->getOrInsertFunction(
                    "__runtime_cleanup", Type::getVoidTy(C));

            auto BB = &(*F.getBasicBlockList().rbegin());
            auto I = &(*BB->getInstList().rbegin());
            IRBuilder<> builder(I);
            builder.SetInsertPoint(I);
            builder.CreateCall(func);
        }

        void addCheckBeforeStoreInst(StoreInst *SI) {
            auto F = SI->getFunction();
            DataLayout DL = F->getParent()->getDataLayout();
            unsigned size = DL.getTypeAllocSize(SI->getValueOperand()->getType());
            errs() << "log: data size " << size << "\n";

            LLVMContext &C = SI->getContext();
            FunctionCallee func = F->getParent()->getOrInsertFunction(
                    "__runtime_check_addr", Type::getVoidTy(C),
                    Type::getInt8PtrTy(C), Type::getInt64Ty(C));

            IRBuilder<> builder(SI);
            builder.SetInsertPoint(SI);
            std::vector<Value*> args{SI->getOperand(1), ConstantInt::get(Type::getInt32Ty(C), size, false)};
            builder.CreateCall(func, args);
        }

        void addCheckBeforeLoadInst(LoadInst *LI) {
            auto F = LI->getFunction();
            DataLayout DL = F->getParent()->getDataLayout();
            unsigned long size = DL.getTypeAllocSize(LI->getType());
            errs() << "log: data size " << size << "\n";

            LLVMContext &C = LI->getContext();
            FunctionCallee func = F->getParent()->getOrInsertFunction(
                    "__runtime_check_addr", Type::getVoidTy(C),
                    Type::getInt8PtrTy(C), Type::getInt64Ty(C));

            IRBuilder<> builder(LI);
            builder.SetInsertPoint(LI);
            auto argPtr = LI->getOperand(0);
            errs() << "debug: arg ptr : " << argPtr << "\n";
            errs() << "debug: arg ptr : " << argPtr->getValueName() << "\n";
            auto argSize = ConstantInt::get(Type::getInt32Ty(C), size, false);
            std::vector<Value*> args{argPtr, argSize};
            builder.CreateCall(func, args);
        }

        void transform(Function &F) {
            if (F.getName() == "main") {
                errs() << "It's main function, add init call\n";
                addInit(F);
            }
            //std::set<Value*> track;
            //errs() << "log: find all malloc value\n";
            //for (auto &B : F) {
            //    for (auto &I: B) {
            //        if (auto *CI = dyn_cast<CallInst>(&I)) {
            //            errs() << "log: invoking function " << CI->getCalledFunction()->getName() << "\n";
            //            if (CI->getCalledFunction()->getName() == "malloc") {
            //                errs() << "log: value name of call " << CI->getValueName() << "\n";
            //                errs() << "log: users\n";
            //                for (auto U: CI->users()) {
            //                    errs() << "log: " << U << "\n";
            //                }
            //            }
            //        }
            //    }
            //}

            auto ignoreList = std::set<Value*>();
            auto globals = F.getParent()->globals();
            errs() << "test: get globals\n";
            for (auto &global : globals) {
                errs() << "test: " << global << " with name " <<  global.getName() << "\n";
                errs() << "test: value name " << global.getValueName() << "\n";
                errs() << "test: value name value " << global.getValueName()->getValue() << "\n";
                ignoreList.insert(global.getValueName()->getValue());
            }
            errs() << "test: global ignore list\n";
            for (auto v : ignoreList) {
                errs() << v << "\n";
            }
            for (auto &B : F) {
                for (auto &I : B) {
                    if (auto *CI = dyn_cast<CallInst>(&I)) {
                        errs() << "log: invoking function " << CI->getCalledFunction()->getName() << "\n";
                        if (CI->getCalledFunction()->getName() == "malloc") {
                            errs() << "log: value name of call " << CI->getValueName() << "\n";
                            //errs() << "log: call return value " << CI->getReturnedArgOperand() << "\n";
                            //errs() << "log: add track for " << CI->getValueName()->getValue() << "\n";
                            errs() << "log: users\n";
                            for (auto U : CI->users()) {
                                errs() << "log: " << U << U->getName() << "\n";
                            }
                            transformMalloc(*CI);
                        } else if (CI->getCalledFunction()->getName() == "free") {
                            transformFree(*CI);
                        }
                    } else if (auto *SI = dyn_cast<StoreInst>(&I)) {
                        errs() << "log: store instr " << *SI << "\n";
                        errs() << "log: ptr operand " << SI->getOperand(1) << "\n";
                        if (ignoreList.find(SI->getOperand(1)) != ignoreList.end()) {
                            errs() << "log: use global, skipping\n";
                        } else {
                            addCheckBeforeStoreInst(SI);
                        }
                    } else if (auto *LI = dyn_cast<LoadInst>(&I)) {
                        errs() << "log: load instr " << *LI << "\n";
                        errs() << "log: ptr operand " << LI->getOperand(0) << "\n";
                        if (ignoreList.find(LI->getOperand(0)) != ignoreList.end()) {
                            errs() << "log: use global, skipping\n";
                        } else {
                            addCheckBeforeLoadInst(LI);
                        }
                    }
                }
            }
            if (F.getName() == "main") {
                errs() << "It's main function, add clean call\n";
                addClean(F);
            }
        }

        PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM) {
            errs() << "Running MemorySafetyPass on function " << F.getName() << "\n";

            transform(F);

            return PreservedAnalyses::all();
        }

        // do not skip this pass for functions annotated with optnone
        static bool isRequired() { return true; }
    };
} // namespace

/// Registration
PassPluginLibraryInfo getPassPluginInfo() {
    const auto callback = [](PassBuilder &PB) {
        PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM, auto) {
                    if (Name == "memory-safety") {
                        FPM.addPass(MemorySafetyPass());
                        return true;
                    }
                    return false;
                });
    };
    return {LLVM_PLUGIN_API_VERSION, "MemorySafetyPass",
            LLVM_VERSION_STRING, callback};
};

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return getPassPluginInfo();
}

#undef DEBUG_TYPE
