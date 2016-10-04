package explode

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/containers/image/docker/reference"
	"github.com/containers/image/image"
	"github.com/containers/image/types"
	"github.com/containers/storage/pkg/archive"
	"github.com/containers/storage/pkg/chrootarchive"
	"github.com/containers/storage/pkg/ioutils"
	"github.com/containers/storage/pkg/stringid"
	"github.com/docker/distribution"
	"github.com/docker/distribution/digest"
	"github.com/docker/distribution/manifest"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/manifest/schema2"
)

var (
	// Transport is the entry point for all of this logic.
	Transport ExplodeTransport = &explodeTransport{}
	// ErrInvalidReference is returned when ParseReference() is passed an
	// empty reference.
	ErrInvalidReference = errors.New("invalid reference")
	// ErrManifestDigestMismatch is returned when GetTargetManifest() is
	// given a digest-based name that doesn't match the manifest we want to
	// supply.
	ErrManifestDigestMismatch = errors.New("manifest digest mismatch")
	// DefaultPath is the default location for storing exploded images.
	DefaultPath = "/var/lib/containers/exploded"
	// MetadataFile is the name of the file in the image's directory which
	// we use to keep track of the root filesystem's BlobInfo and info for
	// other blobs, since that list can differ from the one in the original
	// manifest.
	MetadataFile = "metadata"
	// ManifestFile is the name of the file in the image's directory which
	// we use for storing a manifest that's being copied in.  We'll use
	// parts of it to compute a manifest for the image when we're asked for
	// one.
	ManifestFile = "manifest"
	// SignatureFile is the name of the file in the image's directory which
	// we use for storing signatures that are being copied in.  Right now
	// we don't do much else with them.
	SignaturesFile = "signatures"
	// TagsFile is the name of a file in the image's directory's parent
	// directory.  It holds a JSON-encoded map from tag names to directory
	// names.
	TagsFile = "tags"
	// RootSubdirectory is the name of the subdirectory of an image's
	// directory that we use for storing the composite root filesystem for
	// the image.
	RootSubdirectory = "rootfs"
	// BlobSubdirectory is the name of the subdirectory of an image's
	// directory that we use for storing blobs that are part of the image
	// but which aren't filesystem layers.
	BlobSubdirectory = "blobs"
)

type ExplodeTransport interface {
	types.ImageTransport
	ParseReferencePath(directory, reference string) (types.ImageReference, error)
}

type explodeTransport struct {
	directory string
}

type explodeReference struct {
	transport explodeTransport
	reference string
	tag       string
	directory string
}

type explodeImageMetadata struct {
	Rootfs types.BlobInfo
	Blobs  []string
}

type explodeImage struct {
	reference *explodeReference
	directory string
	tag       string
	blobs     explodeImageMetadata
	image     types.Image
}

func (e *explodeTransport) Name() string {
	return "explode"
}

// ParseReferencePath returns a reference to a location where we'd explode the
// contents of the image, in a non-reversable way, or from where we'd try to
// read its contents.
func (e *explodeTransport) ParseReferencePath(directory, reference string) (types.ImageReference, error) {
	if reference == "" {
		return nil, ErrInvalidReference
	}
	components := strings.FieldsFunc(filepath.Join(directory, reference), func(r rune) bool {
		switch r {
		case ':', '/':
			return true
		}
		return false
	})
	tag := components[len(components)-1]
	directory = filepath.Clean("/" + filepath.Join(components...))
	extantDir, err := e.readTag(filepath.Dir(directory), tag)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if extantDir != "" {
		directory = extantDir
	}
	return &explodeReference{
		transport: explodeTransport{
			directory: directory,
		},
		reference: reference,
		tag:       tag,
		directory: directory,
	}, nil
}

// ParseReference returns a reference to a location where we'd explode the
// contents of the image, in a non-reversable way.
func (e *explodeTransport) ParseReference(reference string) (types.ImageReference, error) {
	return e.ParseReferencePath(DefaultPath, reference)
}

func (e *explodeReference) Transport() types.ImageTransport {
	return &e.transport
}

func (e *explodeReference) StringWithinTransport() string {
	return e.reference
}

func (e *explodeReference) PolicyConfigurationIdentity() string {
	return ""
}

func (e *explodeReference) PolicyConfigurationNamespaces() []string {
	return []string{}
}

func (e *explodeTransport) ValidatePolicyConfigurationScope(scope string) error {
	return nil
}

func (e *explodeReference) DockerReference() reference.Named {
	return nil
}

// Compute the actual path, based on the tag and the directory in which we're
// keeping the tags file.
func (e *explodeTransport) readTag(repodir, tag string) (dir string, err error) {
	tags := make(map[string]string)
	tagdata, err := ioutil.ReadFile(filepath.Join(repodir, TagsFile))
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if (tagdata != nil) && (len(tagdata) > 0) {
		err = json.Unmarshal(tagdata, &tags)
		if err != nil {
			return "", err
		}
	}
	taggedBase, ok := tags[tag]
	if !ok {
		return "", os.ErrNotExist
	}
	return filepath.Join(repodir, taggedBase), nil
}

// Create an image structure, either reading from the image's directory, or
// writing to a temporary one.
func (e *explodeReference) newImage(ctx *types.SystemContext, reading bool) (*explodeImage, error) {
	imagedata := explodeImageMetadata{
		Rootfs: types.BlobInfo{
			Digest: "",
			Size:   -1,
		},
		Blobs: []string{},
	}
	metadata, err := ioutil.ReadFile(filepath.Join(e.directory, MetadataFile))
	if (err != nil) && (reading || !os.IsNotExist(err)) {
		return nil, err
	}
	if metadata != nil && len(metadata) > 0 {
		err = json.Unmarshal(metadata, &imagedata)
		if err != nil {
			return nil, err
		}
	}
	directory := e.directory
	if !reading {
		directory = filepath.Join(filepath.Dir(directory), stringid.GenerateRandomID()+".tmp")
	}
	img := &explodeImage{
		reference: e,
		directory: directory,
		blobs:     imagedata,
		tag:       e.tag,
	}
	img.image, err = image.FromSource(img)
	if err != nil {
		return nil, err
	}
	return img, nil
}

// Record our directory's base name as the destination for a tag, recorded in a
// tag file in the parent of the image's directory.
func (e *explodeImage) grabTag(tag string) error {
	tags := make(map[string]string)
	tagdata, err := ioutil.ReadFile(filepath.Join(filepath.Dir(e.directory), TagsFile))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if (tagdata != nil) && (len(tagdata) > 0) {
		err = json.Unmarshal(tagdata, &tags)
		if err != nil {
			return err
		}
	}
	logrus.Debugf("Setting tag %q in %q", tag, filepath.Join(filepath.Dir(e.directory), TagsFile))
	tags[tag] = filepath.Base(e.directory)
	tagdata, err = json.Marshal(tags)
	if err != nil {
		return err
	}
	return ioutils.AtomicWriteFile(filepath.Join(filepath.Dir(e.directory), TagsFile), tagdata, 0600)
}

// Remove records in the tag file which point to the reference's directory.
func (e *explodeReference) releaseTags(base string) error {
	tags := make(map[string]string)
	tagdata, err := ioutil.ReadFile(filepath.Join(filepath.Dir(e.directory), TagsFile))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if (tagdata != nil) && (len(tagdata) > 0) {
		err = json.Unmarshal(tagdata, &tags)
		if err != nil {
			return err
		}
	}
	tag := []string{}
	for t, v := range tags {
		if v == base {
			logrus.Debugf("Unsetting tag %q in %q", t, filepath.Join(filepath.Dir(e.directory), TagsFile))
			tag = append(tag, t)
		}
	}
	for _, t := range tag {
		delete(tags, t)
	}
	tagdata, err = json.Marshal(tags)
	if err != nil {
		return err
	}
	return ioutils.AtomicWriteFile(filepath.Join(filepath.Dir(e.directory), TagsFile), tagdata, 0600)
}

func (e *explodeReference) NewImage(ctx *types.SystemContext) (types.Image, error) {
	return e.newImage(ctx, true)
}

func (e *explodeReference) NewImageSource(ctx *types.SystemContext, requestedManifestMIMETypes []string) (types.ImageSource, error) {
	return e.newImage(ctx, true)
}

func (e *explodeReference) NewImageDestination(ctx *types.SystemContext) (types.ImageDestination, error) {
	return e.newImage(ctx, false)
}

// Very carefully delete the files associated with this one image, and then its
// directory.  If there are other things above it, leave them be.
func (e *explodeReference) DeleteImage(*types.SystemContext) error {
	if err := e.releaseTags(filepath.Base(e.directory)); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(e.directory, MetadataFile)); err != nil && !os.IsNotExist(err) {
		logrus.Debugf("Remove %q: %v", filepath.Join(e.directory, MetadataFile), err)
		return err
	}
	if err := os.Remove(filepath.Join(e.directory, ManifestFile)); err != nil && !os.IsNotExist(err) {
		logrus.Debugf("Remove %q: %v", filepath.Join(e.directory, ManifestFile), err)
		return err
	}
	if err := os.Remove(filepath.Join(e.directory, SignaturesFile)); err != nil && !os.IsNotExist(err) {
		logrus.Debugf("Remove %q: %v", filepath.Join(e.directory, SignaturesFile), err)
		return err
	}
	if err := os.RemoveAll(filepath.Join(e.directory, RootSubdirectory)); err != nil && !os.IsNotExist(err) {
		logrus.Debugf("RemoveAll %q: %v", filepath.Join(e.directory, RootSubdirectory), err)
		return err
	}
	if err := os.RemoveAll(filepath.Join(e.directory, BlobSubdirectory)); err != nil && !os.IsNotExist(err) {
		logrus.Debugf("RemoveAll %q: %v", filepath.Join(e.directory, BlobSubdirectory), err)
		return err
	}
	if err := os.Remove(e.directory); err != nil && !os.IsNotExist(err) {
		logrus.Debugf("Remove %q: %v", e.directory, err)
		return err
	}
	logrus.Debugf("Removed %q", e.directory)
	return nil
}

// Methods we don't implement ourselves.
func (e *explodeImage) Manifest() ([]byte, string, error) {
	return e.image.Manifest()
}

func (e *explodeImage) Signatures() ([][]byte, error) {
	return e.image.Signatures()
}

func (e *explodeImage) ConfigInfo() types.BlobInfo {
	return e.image.ConfigInfo()
}

func (e *explodeImage) LayerInfos() []types.BlobInfo {
	return e.image.LayerInfos()
}

// Make sure that, even if we botched the image configuration, we don't return
// null maps in the inspect info.
func (e *explodeImage) Inspect() (*types.ImageInspectInfo, error) {
	info, err := e.image.Inspect()
	if err != nil {
		return nil, err
	}
	if info.Labels == nil {
		info.Labels = make(map[string]string)
	}
	return info, err
}

func (e *explodeImage) UpdatedImage(options types.ManifestUpdateOptions) (types.Image, error) {
	return e.image.UpdatedImage(options)
}

// Methods shared by sources and destinations.

func (e *explodeImage) Reference() types.ImageReference {
	return e.reference
}

func (e *explodeImage) Close() {
	// If we were writing, but didn't commit the results, clean up.
	if strings.HasSuffix(e.directory, ".tmp") {
		if err := os.RemoveAll(e.directory); err != nil {
			logrus.Debugf("Error removing %q: %v", e.directory, err)
		}
	}
}

// Destination methods.

func (e *explodeImage) SupportedManifestMIMETypes() []string {
	return []string{
		schema1.MediaTypeManifest,
		schema2.MediaTypeManifest,
	}
}

func (e *explodeImage) SupportsSignatures() error {
	// We support writing them, but not reading them.
	return nil
}

func (e *explodeImage) ShouldCompressLayers() bool {
	// We're just going to decompress incoming layers anyway.
	return false
}

// Save either a filesystem layer or some other item contained in an image.
func (e *explodeImage) PutBlob(stream io.Reader, inputInfo types.BlobInfo) (types.BlobInfo, error) {
	errorBlobInfo := types.BlobInfo{
		Size: -1,
	}
	var fsize int64
	header := make([]byte, 10240)
	n, err := stream.Read(header)
	if err != nil && err != io.EOF {
		return errorBlobInfo, err
	}
	digester := sha256.New()
	defragmented := io.TeeReader(io.MultiReader(bytes.NewReader(header[:n]), stream), digester)
	if archive.IsArchive(header[:n]) {
		// Apply the layer directly on top of whatever we already have.
		target := filepath.Join(e.directory, RootSubdirectory)
		err = os.MkdirAll(target, 0700)
		if err != nil {
			return errorBlobInfo, err
		}
		logrus.Debugf("Applying layer %q to rootfs %q", inputInfo.Digest, target)
		fsize, err = chrootarchive.ApplyLayer(target, defragmented)
		if err != nil {
			return errorBlobInfo, err
		}
		// Make sure we'll recompute rootfs blob info.
		e.blobs.Rootfs.Digest = ""
	} else {
		// Save the file, which we're pretty sure is not a layer.
		if archive.DetectCompression(header[:n]) != archive.Uncompressed {
			defragmented, err = archive.DecompressStream(defragmented)
			if err != nil {
				return errorBlobInfo, err
			}
		}
		filename := base64.StdEncoding.EncodeToString([]byte(inputInfo.Digest))
		target := filepath.Join(e.directory, BlobSubdirectory)
		err = os.MkdirAll(target, 0700)
		if err != nil {
			return errorBlobInfo, err
		}
		target = filepath.Join(e.directory, BlobSubdirectory, filename)
		file, err := os.Create(target)
		if err != nil {
			return errorBlobInfo, err
		}
		logrus.Debugf("Saving blob %q to %q", inputInfo.Digest, target)
		fsize, err = io.Copy(file, defragmented)
		file.Close()
		if err != nil {
			os.Remove(target)
			return errorBlobInfo, err
		}
		// Make a note of the blob.
		sum := digester.Sum(nil)
		digest := "sha256:" + hex.EncodeToString(sum[:])
		e.blobs.Blobs = append(e.blobs.Blobs, digest)
	}
	sum := digester.Sum(nil)
	return types.BlobInfo{
		Digest: "sha256:" + hex.EncodeToString(sum[:]),
		Size:   fsize,
	}, nil
}

// Save the manifest.
func (e *explodeImage) PutManifest(mdata []byte) error {
	if err := os.MkdirAll(e.directory, 0700); err != nil {
		return err
	}
	return ioutils.AtomicWriteFile(filepath.Join(e.directory, ManifestFile), mdata, 0600)
}

// Save the signatures.
func (e *explodeImage) PutSignatures(signatures [][]byte) error {
	if err := os.MkdirAll(e.directory, 0700); err != nil {
		return err
	}
	sigdata, err := json.Marshal(signatures)
	if err != nil {
		return err
	}
	return ioutils.AtomicWriteFile(filepath.Join(e.directory, SignaturesFile), sigdata, 0600)
}

// Recompute our rootfs's digest, and rename our writing directory to match the
// digest of the manifest.  If there's already a directory with that name,
// assume we're a duplicate.  (Different images with the same filesystem can
// have different image configurations, so we had to stop using the rootfs
// layer's digest for this.  The manifest containers the layer blob's sum
// anyway.)
func (e *explodeImage) Commit() error {
	if e.blobs.Rootfs.Digest != "" {
		// No need to recompute the rootfs blob info.
		return nil
	}
	digester := sha256.New()
	source := filepath.Join(e.directory, RootSubdirectory)
	err := os.MkdirAll(source, 0700)
	if err != nil {
		return err
	}
	reader, err := archive.Tar(source, archive.Gzip)
	if err != nil {
		return err
	}
	logrus.Debugf("Recomputing digest for rootfs layer blob")
	fsize, err := io.Copy(digester, reader)
	if err != nil {
		return err
	}
	sum := digester.Sum(nil)
	e.blobs.Rootfs.Digest = "sha256:" + hex.EncodeToString(sum[:])
	e.blobs.Rootfs.Size = fsize
	logrus.Debugf("Rootfs is %q, size=%d", e.blobs.Rootfs.Digest, e.blobs.Rootfs.Size)
	// Save the blob info.
	blobs, err := json.Marshal(e.blobs)
	if err != nil {
		return err
	}
	err = ioutils.AtomicWriteFile(filepath.Join(e.directory, MetadataFile), blobs, 0600)
	if err != nil {
		return err
	}
	// Try to read the manifest back, to hash it instead.
	if mdata, err := ioutil.ReadFile(filepath.Join(e.directory, ManifestFile)); err == nil {
		sum256 := sha256.Sum256(mdata)
		sum = sum256[:]
	}
	// Try to rename the directory to match the manifest's digest.
	newDirectory := filepath.Join(filepath.Dir(e.directory), hex.EncodeToString(sum[:]))
	logrus.Debugf("Renaming %q to %q", e.directory, newDirectory)
	if err = os.Rename(e.directory, newDirectory); err != nil {
		if !os.IsExist(err) {
			logrus.Debugf("Failed to rename %q to %q: %v", e.directory, newDirectory, err)
			return err
		}
		logrus.Debugf("Image is a duplicate, removing %q", e.directory)
		err = os.RemoveAll(e.directory)
		if err != nil {
			logrus.Debugf("Failed to remove %q: %v", e.directory, err)
			return err
		}
	}
	e.directory = newDirectory
	// Lastly, update the parent directory's tags file.
	return e.grabTag(e.tag)
}

// Source methods.

func (e *explodeImage) GetManifest() ([]byte, string, error) {
	// Read the original manifest's version.
	mdata, err := ioutil.ReadFile(filepath.Join(e.directory, ManifestFile))
	if err != nil {
		logrus.Debugf("No manifest in %q: %v", e.directory, err)
		return nil, "", err
	}
	versioned := manifest.Versioned{}
	err = json.Unmarshal(mdata, &versioned)
	// Convert our rootfs digest string to a Digest.
	rootfs, err := digest.ParseDigest(e.blobs.Rootfs.Digest)
	if err != nil {
		logrus.Debugf("Error parsing rootfs digest %q: %v", e.blobs.Rootfs.Digest, err)
		return nil, "", err
	}
	// Now build either a v1 or v2 manifest, matching our source.
	switch versioned.SchemaVersion {
	case 1:
		manifest1 := schema1.Manifest{
			Versioned: schema1.SchemaVersion,
			FSLayers: []schema1.FSLayer{{
				BlobSum: rootfs,
			}},
		}
		originalManifest1 := schema1.Manifest{}
		err = json.Unmarshal(mdata, &originalManifest1)
		if err == nil {
			manifest1.Name = originalManifest1.Name
			manifest1.Tag = originalManifest1.Tag
			manifest1.Architecture = originalManifest1.Architecture
			// Squash the history down as best we can.
			raw := make(map[string]*json.RawMessage)
			for _, history := range originalManifest1.History {
				config := history.V1Compatibility
				if err := json.Unmarshal([]byte(config), &raw); err != nil {
					logrus.Debugf("Unmarshalling raw config: %v", err)
				}
			}
			// ... except we can't have a parent layer any more.
			delete(raw, "parent")
			newConfig, err := json.Marshal(raw)
			if err != nil {
				logrus.Debugf("Remarshalling raw config: %v", err)
			}
			manifest1.History = append(manifest1.History, schema1.History{V1Compatibility: string(newConfig)})
		}
		json, err := json.Marshal(&manifest1)
		return json, schema1.MediaTypeManifest, err
	case 2:
		originalManifest2 := schema2.Manifest{}
		err = json.Unmarshal(mdata, &originalManifest2)
		if err != nil {
			logrus.Debugf("Unmarshalling raw config: %v", err)
		}
		manifest2 := schema2.Manifest{
			Versioned: schema2.SchemaVersion,
			Config:    originalManifest2.Config,
			Layers: []distribution.Descriptor{{
				MediaType: schema2.MediaTypeLayer,
				Size:      e.blobs.Rootfs.Size,
				Digest:    rootfs,
			}},
		}
		deserialized, err := schema2.FromStruct(manifest2)
		if err != nil {
			logrus.Debugf("Error building manifest: %v", err)
			return nil, "", err
		}
		json, err := deserialized.MarshalJSON()
		if err != nil {
			logrus.Debugf("Error building manifest JSON: %v", err)
			return nil, "", err
		}
		return json, schema2.MediaTypeManifest, err
	}
	return nil, "", os.ErrNotExist
}

func (e *explodeImage) GetBlob(digest string) (io.ReadCloser, int64, error) {
	// Check if it matches our root filesystem.
	err := e.Commit()
	if err != nil {
		return nil, -1, err
	}
	if digest == e.blobs.Rootfs.Digest {
		// Export the entire rootfs.
		source := filepath.Join(e.directory, RootSubdirectory)
		logrus.Debugf("Reading blob layer from %q", source)
		reader, err := archive.Tar(source, archive.Gzip)
		return reader, e.blobs.Rootfs.Size, err
	}
	// Check if we have a blob file by that digest.
	filename := base64.StdEncoding.EncodeToString([]byte(digest))
	source := filepath.Join(e.directory, BlobSubdirectory, filename)
	if file, err := os.Open(source); err == nil {
		stats, err := file.Stat()
		if err != nil {
			file.Close()
			return nil, -1, err
		}
		logrus.Debugf("Reading blob %q", source)
		return file, stats.Size(), nil
	}
	logrus.Debugf("Unable to find blob %q", digest)
	return nil, -1, os.ErrNotExist
}

func (e *explodeImage) GetSignatures() ([][]byte, error) {
	return [][]byte{}, nil
}

func (e *explodeImage) GetTargetManifest(manifestDigest string) (manifest []byte, MIMEType string, err error) {
	requested, err := digest.ParseDigest(manifestDigest)
	if err != nil {
		return nil, "", err
	}
	manifest, mimeType, err := e.GetManifest()
	digest := requested.Algorithm().FromBytes(manifest)
	if digest != requested {
		return nil, "", ErrManifestDigestMismatch
	}
	return manifest, mimeType, err
}

func (s *explodeImage) IsMultiImage() bool {
	return false
}
