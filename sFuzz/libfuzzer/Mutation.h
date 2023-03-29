#pragma once
#include "Common.h"
#include "ContractABI.h"
#include "Dictionary.h"
#include "FuzzItem.h"
#include "TargetContainer.h"
#include <vector>

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer
{
using Dicts = tuple<Dictionary /* code */, Dictionary /* address */>;
class Mutation
{
    FuzzItem curFuzzItem;
    Dicts dicts;
    uint64_t effCount = 0;
    bytes eff;
    void flipbit(int pos);

public:
    uint64_t dataSize = 0;
    uint64_t stageMax = 0;
    uint64_t stageCur = 0;
    uint64_t stageCurByte = 0;
    string stageName = "";
    static uint64_t stageCycles[32];
    bool shadowMode;
    // branch mask
    u8* branchMask = 0;
    u8* origBranchMask = 0;
    u32* positionMap = NULL;

    Mutation(FuzzItem item, Dicts dicts, bool shadow_mode);
    u8* alloc_branchMask(u32 size);
    u32 get_random_modifiable_posn(
        u32 num2Modify, u8 modType, u32 mapLen, u8* branch_mask, u32* position_map);
    u32 get_random_insert_posn(u32 mapLen, u8* branch_mask, u32* position_map);
    void singleWalkingBit(OnMutateFunc cb);
    void twoWalkingBit(OnMutateFunc cb);
    void fourWalkingBit(OnMutateFunc cb);
    void singleWalkingByte(OnMutateFunc cb);
    void twoWalkingByte(OnMutateFunc cb);
    void fourWalkingByte(OnMutateFunc cb);
    void singleArith(OnMutateFunc cb);
    void twoArith(OnMutateFunc cb);
    void fourArith(OnMutateFunc cb);
    void singleInterest(OnMutateFunc cb);
    void twoInterest(OnMutateFunc cb);
    void fourInterest(OnMutateFunc cb);
    void overwriteWithAddressDictionary(OnMutateFunc cb);
    void overwriteWithDictionary(OnMutateFunc cb);
    void random(OnMutateFunc cb);
    void havoc(OnMutateFunc cb);
    bool splice(vector<FuzzItem> items);
    bool prolongate(vector<FuzzItem> items, ContractABI* pca, OnMutateFunc cb);
};
}  // namespace fuzzer
