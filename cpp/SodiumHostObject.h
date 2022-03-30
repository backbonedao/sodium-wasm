#ifndef SODIUMHOSTOBJECT_H
#define SODIUMHOSTOBJECT_H

#include <jsi/jsi.h>

namespace screamingvoid {

using namespace facebook::jsi;

class JSI_EXPORT SodiumHostObject: public HostObject {
public:
    explicit SodiumHostObject();

public:
    std::vector<PropNameID> getPropertyNames(Runtime& rt) override;
    Value get(Runtime&, const PropNameID& name) override;
};

} // namespace mscreamingvoidargelo

#endif /* SODIUMHOSTOBJECT_H */
