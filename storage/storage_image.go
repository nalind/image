package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/Sirupsen/logrus"
	"github.com/containers/image/image"
	"github.com/containers/image/manifest"
	"github.com/containers/image/types"
	"github.com/containers/storage"
	"github.com/containers/storage/pkg/archive"
	"github.com/containers/storage/pkg/ioutils"
	digest "github.com/opencontainers/go-digest"
	imgspec "github.com/opencontainers/image-spec/specs-go"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

var (
	// ErrBlobDigestMismatch is returned when PutBlob() is given a blob
	// with a digest-based name that doesn't match its contents.
	ErrBlobDigestMismatch = errors.New("blob digest mismatch")
	// ErrBlobSizeMismatch is returned when PutBlob() is given a blob
	// with an expected size that doesn't match the reader.
	ErrBlobSizeMismatch = errors.New("blob size mismatch")
	// ErrNoManifestLists is returned when GetTargetManifest() is called.
	ErrNoManifestLists = errors.New("manifest lists are not supported by this transport")
	// ErrNoSuchImage is returned when we attempt to access an image which
	// doesn't exist in the storage area.
	ErrNoSuchImage = storage.ErrNotAnImage
)

type storageImageSource struct {
	image *storageImage
}

type storageImageDestination struct {
	image          types.Image
	imageRef       storageReference
	directory      string                          // Temporary directory where we store blobs until Commit() time
	counter        int32                           // A counter that we use for computing filenames to assign to blobs
	manifest       []byte                          // Manifest contents, temporary
	signatures     []byte                          // Signature contents, temporary
	blobOrder      []digest.Digest                 // List of layer blobsums, in the order they were put
	blobDiffIDs    map[digest.Digest]digest.Digest // Mapping from layer blobsums to their corresponding DiffIDs
	fileSizes      map[digest.Digest]int64         // Mapping from layer blobsums to their sizes
	filenames      map[digest.Digest]string        // Mapping from layer blobsums to names of files we used to hold them
	SignatureSizes []int                           `json:"signature-sizes"` // List of sizes of each signature slice
}

type storageImage struct {
	types.Image
	reader *storageImageReader
	size   int64
}

type storageImageReader struct {
	ID             string
	imageRef       storageReference
	layerPosition  map[digest.Digest]int // Where we are in reading a blob's layers
	SignatureSizes []int                 `json:"signature-sizes"` // List of sizes of each signature slice
}

// newImageReader sets us up to read out an image without making any changes to what we read before
// handing it back to the caller.
func newImageReader(imageRef storageReference) (*storageImageReader, error) {
	img, err := imageRef.resolveImage()
	if err != nil {
		return nil, err
	}
	image := &storageImageReader{
		ID:             img.ID,
		imageRef:       imageRef,
		layerPosition:  make(map[digest.Digest]int),
		SignatureSizes: []int{},
	}
	if err := json.Unmarshal([]byte(img.Metadata), image); err != nil {
		return nil, errors.Wrap(err, "error decoding metadata for source image")
	}
	return image, nil
}

// Reference returns the image reference that we used to find this image.
func (s storageImageReader) Reference() types.ImageReference {
	return s.imageRef
}

// Close cleans up any resources we tied up while reading the image.
func (s storageImageReader) Close() error {
	return nil
}

// GetBlob reads the data blob or filesystem layer which matches the digest and size, if given.
func (s *storageImageReader) GetBlob(info types.BlobInfo) (rc io.ReadCloser, n int64, err error) {
	rc, n, _, err = s.getBlobAndLayerID(info, false)
	return rc, n, err
}

// GetBlob reads the data blob or filesystem layer which matches the digest and size, if given, and returns
// the layer ID for the layer, if it was a layer.
func (s *storageImageReader) getBlobAndLayerID(info types.BlobInfo, decompress bool) (rc io.ReadCloser, n int64, layerID string, err error) {
	var layer storage.Layer
	var diffOptions *storage.DiffOptions
	// We need a valid digest value.
	err = info.Digest.Validate()
	if err != nil {
		return nil, -1, "", err
	}
	// Check if the blob corresponds to a diff that was used to initialize any layers, either
	// before or after decompression, since we don't care.
	uncompressedLayers, err := s.imageRef.transport.store.LayersByUncompressedDigest(info.Digest)
	compressedLayers, err := s.imageRef.transport.store.LayersByCompressedDigest(info.Digest)
	// If it's not a layer, then it must be a data item.
	if len(uncompressedLayers) == 0 && len(compressedLayers) == 0 {
		b, err := s.imageRef.transport.store.ImageBigData(s.ID, info.Digest.String())
		if err != nil {
			return nil, -1, "", err
		}
		r := bytes.NewReader(b)
		logrus.Debugf("exporting opaque data as blob %q", info.Digest.String())
		return ioutil.NopCloser(r), int64(r.Len()), "", nil
	}
	// Step through each list of matching layers.  Tests may want to verify that if we have multiple layers
	// which claim to have the same contents, that we actually do have multiple layers, otherwise we could
	// just go ahead and use the first one every time.
	i := s.layerPosition[info.Digest]
	s.layerPosition[info.Digest] = i + 1
	if len(uncompressedLayers) > 0 {
		layer = uncompressedLayers[i%len(uncompressedLayers)]
	} else {
		layer = compressedLayers[i%len(compressedLayers)]
	}
	layerID = layer.ID
	// If we've been told to force decompression, do so.
	if decompress {
		noCompression := archive.Uncompressed
		diffOptions = &storage.DiffOptions{
			Compression: &noCompression,
		}
		if layer.UncompressedSize < 0 {
			n = -1
		} else {
			n = layer.UncompressedSize
		}
		logrus.Debugf("exporting filesystem layer %q without compression for blob %q", layerID, info.Digest)
	} else {
		if layer.CompressedSize < 0 {
			n = -1
		} else {
			n = layer.CompressedSize
		}
		logrus.Debugf("exporting filesystem layer %q with default compression (%v) for blob %q", layer.CompressionType, layerID, info.Digest)
	}
	rc, err = s.imageRef.transport.store.Diff("", layerID, diffOptions)
	if err != nil {
		return nil, -1, "", err
	}
	return rc, n, layerID, err
}

// GetManifest() reads the image's manifest.
func (s *storageImageReader) GetManifest() (manifestBlob []byte, MIMEType string, err error) {
	manifestBlob, err = s.imageRef.transport.store.ImageBigData(s.ID, "manifest")
	return manifestBlob, manifest.GuessMIMEType(manifestBlob), err
}

// GetTargetManifest() is not supported.
func (s *storageImageReader) GetTargetManifest(d digest.Digest) (manifestBlob []byte, MIMEType string, err error) {
	return nil, "", ErrNoManifestLists
}

// GetSignatures() parses the image's signatures blob into a slice of byte slices.
func (s *storageImageReader) GetSignatures() (signatures [][]byte, err error) {
	var offset int
	sigslice := [][]byte{}
	signature, err := s.imageRef.transport.store.ImageBigData(s.ID, "signatures")
	if err != nil {
		if !os.IsNotExist(errors.Cause(err)) {
			logrus.Debugf("got error %v looking up signatures for image %q", err, s.ID)
		}
		return sigslice, nil
	}
	for _, length := range s.SignatureSizes {
		sigslice = append(sigslice, signature[offset:offset+length])
		offset += length
	}
	if offset != len(signature) {
		return nil, errors.Errorf("signatures data contained %d extra bytes", len(signatures)-offset)
	}
	return sigslice, nil
}

// getSize() adds up the sizes of the image's data blobs (which includes the configuration blob), the
// signatures, and the uncompressed sizes of all of the image's layers.
func (s *storageImageReader) getSize() (int64, error) {
	var sum int64
	// Size up the data blobs.
	dataNames, err := s.imageRef.transport.store.ListImageBigData(s.ID)
	if err != nil {
		return -1, errors.Wrapf(err, "error reading image %q", s.ID)
	}
	for _, dataName := range dataNames {
		bigSize, err := s.imageRef.transport.store.ImageBigDataSize(s.ID, dataName)
		if err != nil {
			return -1, errors.Wrapf(err, "error reading data blob size %q for %q", dataName, s.ID)
		}
		sum += bigSize
	}
	// Add the signature sizes.
	for _, sigSize := range s.SignatureSizes {
		sum += int64(sigSize)
	}
	// Prepare to walk the layer list.
	img, err := s.imageRef.transport.store.Image(s.ID)
	if err != nil {
		return -1, errors.Wrapf(err, "error reading image info %q", s.ID)
	}
	// Walk the layer list.
	layerID := img.TopLayer
	for layerID != "" {
		layer, err := s.imageRef.transport.store.Layer(layerID)
		if err != nil {
			return -1, err
		}
		if layer.UncompressedSize < 0 {
			return -1, errors.Errorf("size for layer %q is unknown, failing getSize()", layerID)
		}
		sum += layer.UncompressedSize
		if layer.Parent == "" {
			break
		}
		layerID = layer.Parent
	}
	return sum, nil
}

// newImage creates an image that knows its size and always refers to its layer blobs using
// uncompressed digests and sizes
func newImage(s storageReference) (*storageImage, error) {
	reader, err := newImageReader(s)
	if err != nil {
		return nil, err
	}
	// Compute the image's size.
	size, err := reader.getSize()
	if err != nil {
		return nil, err
	}
	// Build the updated information that we want for the manifest.
	simg, err := reader.imageRef.transport.store.Image(reader.ID)
	if err != nil {
		return nil, err
	}
	updatedBlobInfos := []types.BlobInfo{}
	diffIDs := []digest.Digest{}
	layerID := simg.TopLayer
	for layerID != "" {
		layer, err := reader.imageRef.transport.store.Layer(layerID)
		if err != nil {
			return nil, err
		}
		if layer.UncompressedDigest == "" {
			return nil, errors.Errorf("uncompressed digest for layer %q is unknown", layerID)
		}
		blobInfo := types.BlobInfo{
			Digest: layer.UncompressedDigest,
			Size:   layer.UncompressedSize,
		}
		updatedBlobInfos = append([]types.BlobInfo{blobInfo}, updatedBlobInfos...)
		diffIDs = append([]digest.Digest{layer.UncompressedDigest}, diffIDs...)
		if layer.Parent == "" {
			break
		}
		layerID = layer.Parent
	}
	info := types.ManifestUpdateInformation{
		Destination:  nil,
		LayerInfos:   updatedBlobInfos,
		LayerDiffIDs: diffIDs,
	}
	options := types.ManifestUpdateOptions{
		LayerInfos:      updatedBlobInfos,
		InformationOnly: info,
	}
	// Return a version of the image that uses the updated manifest.
	img, err := image.FromSource(reader)
	if err != nil {
		return nil, err
	}
	updated, err := img.UpdatedImage(options)
	if err != nil {
		return nil, err
	}
	return &storageImage{Image: updated, reader: reader, size: size}, nil
}

// Size returns the image's previously-computed size.
func (s *storageImage) Size() (int64, error) {
	return s.size, nil
}

// newImageSource reads an image that has been updated to not compress layers.
func newImageSource(s storageReference) (*storageImageSource, error) {
	image, err := newImage(s)
	if err != nil {
		return nil, err
	}
	return &storageImageSource{image: image}, nil
}

// GetBlob returns either a data blob or an uncompressed layer blob.  In practice this avoids attempting
// to recompress any layers that were originally delivered in compressed form, since we know that we
// updated the manifest to refer to the blob using the digest of the uncompressed version.
func (s *storageImageSource) GetBlob(info types.BlobInfo) (rc io.ReadCloser, n int64, err error) {
	rc, n, _, err = s.image.reader.getBlobAndLayerID(info, true)
	return rc, n, err
}

// GetManifest returns the updated manifest.
func (s *storageImageSource) GetManifest() ([]byte, string, error) {
	return s.image.Manifest()
}

// GetTargetManifest still returns an error.
func (s *storageImageSource) GetTargetManifest(d digest.Digest) (manifestBlob []byte, MIMEType string, err error) {
	return nil, "", ErrNoManifestLists
}

// GetSignatures returns the original signatures.
func (s *storageImageSource) GetSignatures() ([][]byte, error) {
	return s.image.reader.GetSignatures()
}

// Reference returns the image reference that we used to find this image.
func (s storageImageSource) Reference() types.ImageReference {
	return s.image.reader.imageRef
}

// Close cleans up any resources we tied up while reading the image.
func (s *storageImageSource) Close() error {
	return s.image.Close()
}

// newImageDestination sets us up to write a new image, caching blobs in a temporary directory until
// it's time to Commit() the image
func newImageDestination(imageRef storageReference) (*storageImageDestination, error) {
	directory, err := ioutil.TempDir("", "storage")
	if err != nil {
		return nil, errors.Wrapf(err, "error creating a temporary directory")
	}
	image := &storageImageDestination{
		imageRef:       imageRef,
		directory:      directory,
		blobDiffIDs:    make(map[digest.Digest]digest.Digest),
		fileSizes:      make(map[digest.Digest]int64),
		filenames:      make(map[digest.Digest]string),
		SignatureSizes: []int{},
	}
	return image, nil
}

// Reference returns the image reference that we want the resulting image to match.
func (s storageImageDestination) Reference() types.ImageReference {
	return s.imageRef
}

// Close cleans up the temporary directory.
func (s *storageImageDestination) Close() error {
	if s.image != nil {
		img := s.image
		s.image = nil
		img.Close()
	}
	return os.RemoveAll(s.directory)
}

// ShouldCompressLayers indicates whether or not a caller should compress not-already-compressed
// data when handing it to us.
func (s storageImageDestination) ShouldCompressLayers() bool {
	// We ultimately have to decompress layers to populate trees on disk, so callers shouldn't
	// bother compressing them before handing them to us, if they're not already compressed.
	return false
}

// PutBlob stores a layer or data blob in our temporary directory, checking that any information
// in the blobinfo matches the incoming data.
func (s *storageImageDestination) PutBlob(stream io.Reader, blobinfo types.BlobInfo) (types.BlobInfo, error) {
	blobSize := blobinfo.Size
	blobDigest := blobinfo.Digest
	errorBlobInfo := types.BlobInfo{
		Digest: "",
		Size:   -1,
	}
	// Set up to digest the blob and count its size while saving it to a file.
	hasher := digest.Canonical.Digester()
	if blobDigest.Validate() == nil {
		if a := blobDigest.Algorithm(); a.Available() {
			hasher = a.Digester()
		}
	}
	diffID := digest.Canonical.Digester()
	filename := filepath.Join(s.directory, fmt.Sprintf("%d", atomic.AddInt32(&s.counter, 1)))
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return errorBlobInfo, errors.Wrapf(err, "error creating temporary file %q", filename)
	}
	defer file.Close()
	counter := ioutils.NewWriteCounter(hasher.Hash())
	reader := io.TeeReader(io.TeeReader(stream, counter), file)
	decompressed, err := archive.DecompressStream(reader)
	if err != nil {
		return errorBlobInfo, errors.Wrap(err, "error setting up to decompress blob")
	}
	// Copy the data to the file.
	_, err = io.Copy(diffID.Hash(), decompressed)
	decompressed.Close()
	if err != nil {
		return errorBlobInfo, errors.Wrapf(err, "error storing blob to file %q", filename)
	}
	// Ensure that any information that we were given about the blob is correct.
	if blobDigest.Validate() == nil && blobDigest != hasher.Digest() {
		return errorBlobInfo, ErrBlobDigestMismatch
	}
	if blobSize >= 0 && blobSize != counter.Count {
		return errorBlobInfo, ErrBlobSizeMismatch
	}
	// Record information about the blob.
	s.blobOrder = append(s.blobOrder, hasher.Digest())
	s.blobDiffIDs[hasher.Digest()] = diffID.Digest()
	s.fileSizes[hasher.Digest()] = counter.Count
	s.filenames[hasher.Digest()] = filename
	if blobDigest.Validate() != nil {
		blobDigest = hasher.Digest()
	}
	if blobSize < 0 {
		blobSize = counter.Count
	}
	return types.BlobInfo{
		Digest: blobDigest,
		Size:   blobSize,
	}, nil
}

// HasBlob returns true iff the image destination already contains a blob with the matching digest which can be
// reapplied using ReapplyBlob.
//
// Unlike PutBlob, the digest can not be empty.  If HasBlob returns true, the size of the blob must also be returned.
// If the destination does not contain the blob, or it is unknown, HasBlob ordinarily returns (false, -1, nil);
// it returns a non-nil error only on an unexpected failure.
func (s *storageImageDestination) HasBlob(blobinfo types.BlobInfo) (bool, int64, error) {
	if blobinfo.Digest == "" {
		return false, -1, errors.Errorf(`Can not check for a blob with unknown digest`)
	}
	if err := blobinfo.Digest.Validate(); err != nil {
		return false, -1, errors.Wrapf(err, `Can not check for a blob with invalid digest`)
	}
	// Check if we've already cached it in a file.
	if size, ok := s.fileSizes[blobinfo.Digest]; ok {
		return true, size, nil
	}
	// Check if we have a wasn't-compressed layer in storage that's based on that blob.
	layers, err := s.imageRef.transport.store.LayersByUncompressedDigest(blobinfo.Digest)
	if err != nil {
		return false, -1, errors.Wrapf(err, `Error looking for layers with digest %q`, blobinfo.Digest)
	}
	if len(layers) > 0 {
		// Save this for completeness.
		s.blobDiffIDs[blobinfo.Digest] = layers[0].UncompressedDigest
		return true, layers[0].UncompressedSize, nil
	}
	// Check if we have a was-compressed layer in storage that's based on that blob.
	layers, err = s.imageRef.transport.store.LayersByCompressedDigest(blobinfo.Digest)
	if err != nil {
		return false, -1, errors.Wrapf(err, `Error looking for compressed layers with digest %q`, blobinfo.Digest)
	}
	if len(layers) > 0 {
		// Record the uncompressed value so that we can use it to calculate layer IDs.
		s.blobDiffIDs[blobinfo.Digest] = layers[0].UncompressedDigest
		return true, layers[0].CompressedSize, nil
	}
	// Nope, we don't have it.
	return false, -1, nil
}

// ReapplyBlob is now a no-op, assuming PutBlob() says we already have it.
func (s *storageImageDestination) ReapplyBlob(blobinfo types.BlobInfo) (types.BlobInfo, error) {
	present, size, err := s.HasBlob(blobinfo)
	if !present {
		return types.BlobInfo{}, errors.Errorf("error reapplying blob %+v: blob was not previously applied", blobinfo)
	}
	if err != nil {
		return types.BlobInfo{}, errors.Wrapf(err, "error reapplying blob %+v", blobinfo)
	}
	blobinfo.Size = size
	s.blobOrder = append(s.blobOrder, blobinfo.Digest)
	return blobinfo, nil
}

// GetBlob() shouldn't really be called, but include an implementation in case other parts of the library
// start needing it.
func (s *storageImageDestination) GetBlob(blobinfo types.BlobInfo) (rc io.ReadCloser, n int64, err error) {
	if blobinfo.Digest == "" {
		return nil, -1, errors.Errorf(`can't read a blob with unknown digest`)
	}
	if err := blobinfo.Digest.Validate(); err != nil {
		return nil, -1, errors.Wrapf(err, `can't check for a blob with invalid digest`)
	}
	// Check if we've already cached the blob as a file.
	if filename, ok := s.filenames[blobinfo.Digest]; ok {
		f, err := os.Open(filename)
		if err != nil {
			return nil, -1, errors.Wrapf(err, `can't read file %q`, filename)
		}
		return f, -1, nil
	}
	// Check if we have a wasn't-compressed layer in storage that's based on that blob.  If we have one,
	// start reading it.
	layers, err := s.imageRef.transport.store.LayersByUncompressedDigest(blobinfo.Digest)
	if err != nil {
		return nil, -1, errors.Wrapf(err, `error looking for layers with digest %q`, blobinfo.Digest)
	}
	if len(layers) > 0 {
		rc, err := s.imageRef.transport.store.Diff("", layers[0].ID, nil)
		return rc, -1, err
	}
	// Check if we have a was-compressed layer in storage that's based on that blob.  If we have one,
	// start reading it.
	layers, err = s.imageRef.transport.store.LayersByCompressedDigest(blobinfo.Digest)
	if err != nil {
		return nil, -1, errors.Wrapf(err, `error looking for compressed layers with digest %q`, blobinfo.Digest)
	}
	if len(layers) > 0 {
		rc, err := s.imageRef.transport.store.Diff("", layers[0].ID, nil)
		return rc, -1, err
	}
	// Nope, we don't have it.
	return nil, -1, errors.Errorf(`error locating blob with blobsum %q`, blobinfo.Digest.String())
}

func (s *storageImageDestination) Commit() error {
	// Find the list of layer blobs.  We have to implement enough of an ImageSource to be able to
	// parse the manifest to get a list of which blobs are filesystem layers, leaving any cached
	// files that aren't filesystem layers to be saved as data items.
	if s.image == nil {
		img, err := image.FromSource(s)
		if err != nil {
			return errors.Wrapf(err, "error locating manifest for layer blob list")
		}
		s.image = img
	}
	layerBlobs := s.image.LayerInfos()
	// Extract or find the layers.
	lastLayer := ""
	addedLayers := []string{}
	for _, blob := range layerBlobs {
		var diff io.ReadCloser
		// Check if there's already a layer with the ID that we'd give to the result of applying
		// this layer blob to its parent, if it has one, or the blob's hex value otherwise.
		diffID, haveDiffID := s.blobDiffIDs[blob.Digest]
		if !haveDiffID {
			// Check if it's elsewhere and the caller just forgot to pass it to us in a PutBlob(),
			// or to even check if we had it.
			logrus.Debugf("looking for diffID for blob %+v", blob.Digest)
			has, _, err := s.HasBlob(blob)
			if err != nil {
				return errors.Wrapf(err, "error checking for a layer based on blob %q", blob.Digest.String())
			}
			if !has {
				return errors.Errorf("error determining uncompressed digest for blob %q", blob.Digest.String())
			}
			diffID, haveDiffID = s.blobDiffIDs[blob.Digest]
			if !haveDiffID {
				return errors.Errorf("we have blob %q, but don't know its uncompressed digest", blob.Digest.String())
			}
		}
		id := diffID.Hex()
		if lastLayer != "" {
			id = digest.Canonical.FromBytes([]byte(lastLayer + "+" + diffID.Hex())).Hex()
		}
		if layer, err2 := s.imageRef.transport.store.Layer(id); layer != nil && err2 == nil {
			// There's already a layer that should have the right contents, just reuse it.
			lastLayer = layer.ID
			continue
		}
		// Check if we cached a file with that blobsum.  If we didn't already have a layer with
		// the blob's contents, we should have gotten a copy.
		if filename, ok := s.filenames[blob.Digest]; ok {
			// Use the file's contents to initialize the layer.
			file, err2 := os.Open(filename)
			if err2 != nil {
				return errors.Wrapf(err2, "error opening file %q", filename)
			}
			defer file.Close()
			diff = file
		}
		if diff == nil {
			// Try to find a layer with contents matching that blobsum.
			layer := ""
			layers, err2 := s.imageRef.transport.store.LayersByUncompressedDigest(blob.Digest)
			if err2 == nil && len(layers) > 0 {
				layer = layers[0].ID
			} else {
				layers, err2 = s.imageRef.transport.store.LayersByCompressedDigest(blob.Digest)
				if err2 == nil && len(layers) > 0 {
					layer = layers[0].ID
				}
			}
			if layer == "" {
				return errors.Wrapf(err2, "error locating layer for blob %q", blob.Digest)
			}
			// Use the layer's contents to initialize the new layer.
			noCompression := archive.Uncompressed
			diffOptions := &storage.DiffOptions{
				Compression: &noCompression,
			}
			diff, err2 = s.imageRef.transport.store.Diff("", layer, diffOptions)
			if err2 != nil {
				return errors.Wrapf(err2, "error reading layer %q for blob %q", layer, blob.Digest)
			}
			defer diff.Close()
		}
		if diff == nil {
			// This shouldn't have happened.
			return errors.Errorf("error applying blob %q: content not found", blob.Digest)
		}
		// Build the new layer using the diff, regardless of where it came from.
		layer, _, err := s.imageRef.transport.store.PutLayer(id, lastLayer, nil, "", false, diff)
		if err != nil {
			return errors.Wrapf(err, "error adding layer with blob %q", blob.Digest)
		}
		lastLayer = layer.ID
		addedLayers = append([]string{lastLayer}, addedLayers...)
	}
	// If one of those blobs was a configuration blob, then we can try to dig out the date when the image
	// was originally created, in case we're just copying it.  If not, no harm done.
	var options *storage.ImageOptions
	if inspect, err := s.image.Inspect(); err == nil {
		logrus.Debugf("setting image creation date to %s", inspect.Created)
		options = &storage.ImageOptions{
			CreationDate: inspect.Created,
		}
	}
	// Create the image record, pointing to the most-recently added layer.
	intendedID := s.imageRef.id
	if configInfo := s.image.ConfigInfo(); intendedID == "" && configInfo.Digest.Validate() == nil {
		intendedID = configInfo.Digest.Hex()
	}
	oldNames := []string{}
	img, err := s.imageRef.transport.store.CreateImage(intendedID, nil, lastLayer, "", options)
	if err != nil {
		if errors.Cause(err) != storage.ErrDuplicateID {
			logrus.Debugf("error creating image: %q", err)
			return errors.Wrapf(err, "error creating image %q", intendedID)
		}
		img, err = s.imageRef.transport.store.Image(intendedID)
		if err != nil {
			return errors.Wrapf(err, "error reading image %q", intendedID)
		}
		if img.TopLayer != lastLayer {
			logrus.Debugf("error creating image: image with ID %q exists, but uses different layers", intendedID)
			return errors.Wrapf(storage.ErrDuplicateID, "image with ID %q already exists, but uses a different top layer", intendedID)
		}
		logrus.Debugf("reusing image ID %q", img.ID)
		oldNames = append(oldNames, img.Names...)
	} else {
		logrus.Debugf("created new image ID %q", img.ID)
	}
	// Add the non-layer blobs as data items.  Since we only share layers, they should all be in files, so
	// we just need to screen out the ones that are actually layers to get the list of non-layers.
	dataBlobs := make(map[digest.Digest]struct{})
	for blob := range s.filenames {
		dataBlobs[blob] = struct{}{}
	}
	for _, layerBlob := range layerBlobs {
		delete(dataBlobs, layerBlob.Digest)
	}
	for blob := range dataBlobs {
		v, err := ioutil.ReadFile(s.filenames[blob])
		if err != nil {
			return errors.Wrapf(err, "error copying non-layer blob %q to image", blob)
		}
		if err := s.imageRef.transport.store.SetImageBigData(img.ID, blob.String(), v); err != nil {
			if _, err2 := s.imageRef.transport.store.DeleteImage(img.ID, true); err2 != nil {
				logrus.Debugf("error deleting incomplete image %q: %v", img.ID, err2)
			}
			logrus.Debugf("error saving big data %q for image %q: %v", blob.String(), img.ID, err)
			return errors.Wrapf(err, "error saving big data %q for image %q", blob.String(), img.ID)
		}
	}
	// Set the reference's name on the image.
	if name := s.imageRef.DockerReference(); name != nil {
		names := append([]string{verboseName(name)}, oldNames...)
		if err := s.imageRef.transport.store.SetNames(img.ID, names); err != nil {
			if _, err2 := s.imageRef.transport.store.DeleteImage(img.ID, true); err2 != nil {
				logrus.Debugf("error deleting incomplete image %q: %v", img.ID, err2)
			}
			logrus.Debugf("error setting names %v on image %q: %v", names, img.ID, err)
			return errors.Wrapf(err, "error setting names %v on image %q", names, img.ID)
		}
		logrus.Debugf("set names of image %q to %v", img.ID, names)
	}
	// Save the manifest.
	manifest, _, err := s.GetManifest()
	if err != nil {
		manifest = s.manifest
	}
	if err := s.imageRef.transport.store.SetImageBigData(img.ID, "manifest", manifest); err != nil {
		if _, err2 := s.imageRef.transport.store.DeleteImage(img.ID, true); err2 != nil {
			logrus.Debugf("error deleting incomplete image %q: %v", img.ID, err2)
		}
		logrus.Debugf("error saving manifest for image %q: %v", img.ID, err)
		return err
	}
	// Save the signatures, if we have any.
	if len(s.signatures) > 0 {
		if err := s.imageRef.transport.store.SetImageBigData(img.ID, "signatures", s.signatures); err != nil {
			if _, err2 := s.imageRef.transport.store.DeleteImage(img.ID, true); err2 != nil {
				logrus.Debugf("error deleting incomplete image %q: %v", img.ID, err2)
			}
			logrus.Debugf("error saving signatures for image %q: %v", img.ID, err)
			return err
		}
	}
	// Save our metadata.
	metadata, err := json.Marshal(s)
	if err != nil {
		if _, err2 := s.imageRef.transport.store.DeleteImage(img.ID, true); err2 != nil {
			logrus.Debugf("error deleting incomplete image %q: %v", img.ID, err2)
		}
		logrus.Debugf("error encoding metadata for image %q: %v", img.ID, err)
		return err
	}
	if len(metadata) != 0 {
		if err = s.imageRef.transport.store.SetMetadata(img.ID, string(metadata)); err != nil {
			if _, err2 := s.imageRef.transport.store.DeleteImage(img.ID, true); err2 != nil {
				logrus.Debugf("error deleting incomplete image %q: %v", img.ID, err2)
			}
			logrus.Debugf("error saving metadata for image %q: %v", img.ID, err)
			return err
		}
		logrus.Debugf("saved image metadata %q", string(metadata))
	}
	return nil
}

var manifestMIMETypes = []string{
	imgspecv1.MediaTypeImageManifest,
	manifest.DockerV2Schema2MediaType,
	manifest.DockerV2Schema1SignedMediaType,
	manifest.DockerV2Schema1MediaType,
}

func (s *storageImageDestination) SupportedManifestMIMETypes() []string {
	return manifestMIMETypes
}

// GetManifest reads the manifest that we intend to store.  If we haven't been given one (yet?),
// generate one.
func (s *storageImageDestination) GetManifest() ([]byte, string, error) {
	if len(s.manifest) == 0 {
		m := imgspecv1.Manifest{
			Versioned: imgspec.Versioned{
				SchemaVersion: 2,
			},
			Annotations: make(map[string]string),
		}
		for _, blob := range s.blobOrder {
			desc := imgspecv1.Descriptor{
				MediaType: imgspecv1.MediaTypeImageLayer,
				Digest:    blob,
				Size:      -1,
			}
			m.Layers = append(m.Layers, desc)
		}
		encoded, err := json.Marshal(m)
		if err != nil {
			return nil, "", errors.Wrapf(err, "no manifest written yet, and got an error encoding a temporary one")
		}
		s.manifest = encoded
	}
	return s.manifest, manifest.GuessMIMEType(s.manifest), nil
}

// GetTargetManifest reads a manifest among several that we might intend to store.
func (s *storageImageDestination) GetTargetManifest(targetDigest digest.Digest) ([]byte, string, error) {
	if len(s.manifest) == 0 {
		return nil, "", errors.Errorf("no manifest written yet")
	}
	if digest.Canonical.FromBytes(s.manifest) != targetDigest {
		return nil, "", errors.Errorf("no matching target manifest")
	}
	return s.manifest, manifest.GuessMIMEType(s.manifest), nil
}

// PutManifest writes the manifest to the destination.
func (s *storageImageDestination) PutManifest(manifest []byte) error {
	s.manifest = make([]byte, len(manifest))
	copy(s.manifest, manifest)
	return nil
}

// SupportsSignatures returns an error if we can't expect GetSignatures() to return data that was
// previously supplied to PutSignatures().
func (s *storageImageDestination) SupportsSignatures() error {
	return nil
}

// AcceptsForeignLayerURLs returns false iff foreign layers in the manifest should actually be
// uploaded to the image destination, true otherwise.
func (s *storageImageDestination) AcceptsForeignLayerURLs() bool {
	return false
}

// MustMatchRuntimeOS returns true iff the destination can store only images targeted for the current runtime OS. False otherwise.
func (s *storageImageDestination) MustMatchRuntimeOS() bool {
	return true
}

// PutSignatures records the image's signatures for committing as a single data blob.
func (s *storageImageDestination) PutSignatures(signatures [][]byte) error {
	sizes := []int{}
	sigblob := []byte{}
	for _, sig := range signatures {
		sizes = append(sizes, len(sig))
		newblob := make([]byte, len(sigblob)+len(sig))
		copy(newblob, sigblob)
		copy(newblob[len(sigblob):], sig)
		sigblob = newblob
	}
	s.signatures = sigblob
	s.SignatureSizes = sizes
	return nil
}

// GetSignatures splits up the signature blob and returns a slice of byte slices.
func (s *storageImageDestination) GetSignatures() ([][]byte, error) {
	sigs := [][]byte{}
	first := 0
	for _, length := range s.SignatureSizes {
		sigs = append(sigs, s.signatures[first:first+length])
		first += length
	}
	if first == 0 {
		return nil, nil
	}
	return sigs, nil
}
