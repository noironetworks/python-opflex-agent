#!/bin/bash
# Should be run from the root of the source tree

BUILD_DIR=${BUILD_DIR:-`pwd`/rpmbuild}
mkdir -p $BUILD_DIR/BUILD $BUILD_DIR/SOURCES $BUILD_DIR/SPECS $BUILD_DIR/RPMS $BUILD_DIR/SRPMS
RELEASE=${RELEASE:-1}
VERSION=`python3 setup.py --version`
SPEC_FILE=neutron-opflex-agent.spec

# Prepare build scripts for python3
cp rpm/neutron-opflex-agent.spec.in .

sed -i "s/python-/python3-/g" rpm/neutron-opflex-agent.spec.in
sed -i "s/python2/python3/g" rpm/neutron-opflex-agent.spec.in
sed -i "s/Name:           %{srcname}/Name:           python3-%{srcname}/g" rpm/neutron-opflex-agent.spec.in

BUILD_DIR=${BUILD_DIR:-`pwd`/rpmbuild}
mkdir -p $BUILD_DIR/BUILD $BUILD_DIR/SOURCES $BUILD_DIR/SPECS $BUILD_DIR/RPMS $BUILD_DIR/SRPMS
RELEASE=${RELEASE:-1}
VERSION=`python3 setup.py --version`
SPEC_FILE=neutron-opflex-agent.spec
sed -e "s/@VERSION@/$VERSION/" -e "s/@RELEASE@/$RELEASE/" rpm/$SPEC_FILE.in > $BUILD_DIR/SPECS/$SPEC_FILE
python3 setup.py sdist --dist-dir $BUILD_DIR/SOURCES
rpmbuild --clean -ba --define "_topdir $BUILD_DIR" $BUILD_DIR/SPECS/$SPEC_FILE

# Restore the spec file
mv neutron-opflex-agent.spec.in rpm/neutron-opflex-agent.spec.in
